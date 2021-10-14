# Overview

- [说明](#说明)
- [错误代码](#错误代码)
- [解析manifest文件](#解析manifest文件)

<a name="说明"></a>

## 说明

### Changelog

### 返回的数据结构如下
```
{
    "code": 错误代码,
    "result": 任意类型
}
```

`code` 表示的为错误代码, 数字类型

正常返回时`code`为`0`, `result`为数据, 可能是数字, 布尔, 字符串, 数组, 对象等等

错误返回时`code`不为`0`, `result`为错误信息, 字符串类型, 可直接显示在浏览器页面

错误代码原则上前端用不到, 前端仅需要判断非0时显示`result`字段即可


<a name="错误代码"></a>
## 错误代码

|  code     |意义  | 
|  ----   |----  |
| 10101   | 参数错误 |
| 10102   | 服务器内部错误 |

错误代码的第一位, 目前1 标识此应用
错误代码的第二三位, 标识组件
错误代码的第四五位, 标识错误代码

<a name="解析manifest文件"></a>
## 解析manifest文件


### 请求语法
```
POST / HTTP/1.1
```

### 请求参数
|名称|说明|类型|默认值|是否必填|
|---|---|---|---|---|
|content|文件内容|string|无|是|
|instanceid|实例id|string|无|是|
|userconfig|运行时配置|json字符串|"{}"|否|
|dependencies|实例依赖|json字符串|"[]"|否|
|root-domain|根域|string|无|是|

`dependencies[*].instanceid` 内部服务实例id，为string类型，选择内部服务时必填
`dependencies[*].location` 使用方式，为string类型，选择外部服务时必填
`dependencies[*].version` 版本号, string类型，必填
`dependencies[*].uses` 使用的资源和权限， 数组类型，必填
`dependencies[*].entryservice` 服务暴露的组件的名称，string类型，选择内部服务时必填
`dependencies[*].name` 依赖服务的名称，string类型，必填

请求参数示例

* userconfig
```
"{\"username\":\"admin\",\"password\":\"admin\"}"
```

* dependencies
```
"[{\"instanceid\":\"frwugxqd\",\"location\":\"https://gitlab.com\",\"version\":\"0.1.0\",\"uses\":{\"/resource1\":[\"create\",\"get\",\"update\",\"delete\"],\"/resource2\":[\"get\"]},\"entryservice\":\"i1\",\"name\":\"app-demo\"}]"
```

### 返回值
```
{
    "code": 0,
    "result": "yaml内容"
}
```