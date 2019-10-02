# harbor添加管理员漏洞检测工具



## 0x00 概述

201909 harbor爆出可利用注册功能添加管理员漏洞，利用注册接口api/users，构造post参数"has_admin_role":true，可直接添加管理员。

本工具支持单个url或批量检测。



## 0x01 需求

python2.7

pip install requests



## 0x02 快速开始

使用帮助: python harbor-give-me-admin.py -h


![](https://github.com/theLSA/harbor-give-me-admin/raw/master/demo/harbor01.png)


单url检测: python harbor-give-me-admin.py -u "https://www.xxx.com/"
//如利用成功，则会添加管理员帐号test00,谨慎操作！

![](https://github.com/theLSA/harbor-give-me-admin/raw/master/demo/harbor00.png)



批量检测: python harbor-give-me-admin.py -f urls,txt
//如利用成功，则会添加管理员帐号test00,谨慎操作！



## 0x03 反馈

[issus](https://github.com/theLSA/harbor-give-me-admin/issues)

gmail：[lsasguge196@gmail.com](mailto:lsasguge196@gmail.com)

qq：[2894400469@qq.com](mailto:2894400469@qq.com)



