
# Overview

- [说明](#说明)
- [获取管理员信息](#获取管理员信息)
- [修改管理员密码](#修改管理员密码)
- [添加实例](#添加实例)
- [实例列表](#实例列表)
- [实例详情](#实例详情)
- [实例日志](#实例日志)
- [运行实例](#运行实例)
- [删除实例](#删除实例)
- [获取节点地址](#获取节点地址)
- [获取集群根域](#获取集群根域)
- [设置集群根域](#设置集群根域)
- [设置工作负载源](#设置工作负载源)
- [查询工作负载源](#查询工作负载源)

- [流水线接口](#流水线接口)



<a name="说明"></a>
## 说明
### 返回的数据结构如下
```
{
    "code": 错误代码,
    "result": 任意类型
}
```

其中 `code` 表示的为错误代码, 数字类型

正常返回时`code`为`0`, `result`为数据, 可能是数字, 布尔, 字符串, 数组, 对象等等

错误返回时`code`不为`0`, `result`为错误信息, 字符串类型, 可直接显示在浏览器页面

错误代码原则上前端用不到, 前端仅需要判断非0时显示`result`字段即可

接口请求和输出均为JSON格式, 接口的字段为小驼峰命名, 特有名词除外(注意:当前特有名词有`userconfigs`)

<a name="获取管理员信息"></a>
## 获取管理员信息
### 请求语法
```
GET /user/root HTTP/1.1
```
### 请求参数
无

### 返回值
```json
{
    "code": 0,
    "result": {
      "password": "toor",
      "username": "root"
    }
}
```

<a name="修改管理员密码"></a>
## 修改管理员密码
### 请求语法
```
PUT /user/root HTTP/1.1
```
### 请求参数
|名称|说明|默认值|是否必填|
|---|---|---|---|
|password|密码|无|是|
|oldPassword|密码|无|是|
### 请求示例
```json
{
  "password": "admin233",
  "oldPassword": "toor"
}
```
### 返回值
```json
{
    "code": 0,
    "result": "设置成功"
}
```

<a name="添加Trait/WrokloadType/"></a>
## 添加实例
### 请求语法
```
POST /app HTTP/1.1
Content-Type: multipart/form-data; 
```
### 请求参数
|名称|说明|默认值|是否必填|
|---|---|---|---|
|file|实例描述文件（即manifest.yaml文件）|无|是|
### 返回值
```json
{
  "code": 0,
  "result": {
    "id": "ins1635146904",
    "dependencies": {
      "github": {
        "instances": [
          {
            "id": "ins1634971790",
            "name": "github"
          }
        ],
        "location": "https://www.github.com",
        "type": "immutable"
      }
    },
    "userconfigs": {
      "properties": {
        "param1": {
          "type": "integer"
        },
        "param2": {
          "type": "string"
        },
        "param3": {
          "properties": {
            "param3_1": {
              "type": "number"
            },
            "param3_2": {
              "type": "number"
            }
          },
          "required": [
            "param3_1"
          ],
          "type": "object"
        },
        "param4": {
          "items": {
            "type": "string"
          },
          "minItems": 1,
          "type": "array",
          "uniqueItems": true
        }
      },
      "required": [
        "param2"
      ],
      "type": "object"
    }
  }
}
```

该接口的错误返回, 按照全局说明中的错误返回格式处理

<a name="实例列表"></a>
## 实例列表
### 请求语法
```
GET /app?limit=<limit>&offset=<offset> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|offset| |0|否|
|limit|  |10|否|

### 返回值
```json
{
  "code": 0,
  "result": {
    "rows": [
      {
        "id": "ins1634971791",
        "name": "harbor",
        "version": "2.0.0",
        "entry": "http://ins1634971791.example.com",
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      }
    ],
    "total": 1
  }
}
```

<a name="实例详情"></a>
## 实例详情
### 请求语法
```
GET /app/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id| 实例主键 |无|是|

### 返回值

只循环result.pods里的metadata.name即可

```json
{
  "code": 0,
  "result": {
    "id": "ins1634971791",
    "deployment": "[导出K8S描述文件], 前端将此字段信息保存为yaml文件后下载",
    "details": {
      "cronJobs": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }],
      "daemonSets": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }],
      "deployments": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }],
      "jobs": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }],
      "pods": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }],
      "replicaSets": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }],
      "replicationControllers": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }],
      "statefulSets": [{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      },{
        "metadata": {
          "name": "charlie-ndgfb"
        }
      }]
    }
  }
}
```

<a name="实例日志"></a>
## 实例日志
### 请求语法
```
GET /app/<pod>/logs HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|pod| pod名称 |无|是|

### 返回值


```json
{
  "code": 0,
  "result": "春江潮水连海平，海上明月共潮生"
}
```


<a name="运行实例"></a>
## 运行实例
### 请求语法
```
PUT /app/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id| 实例主键 |无|是|

以下参数为BODY参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|dependencies|依赖描述 |无|否|
|userconfigs| 实例自定义配置信息 |无|否|
|status| 实例状态,此处固定为1 |无|是|
#### dependencies 示例
```json
[
    {
		"name": "demo-app1",
		"id": "iqtxycne"
	},
	{
		"name": "demo-app1",
		"location": "https://www.huanqiu.com"
	}
]
```
#### userconfigs 示例
```json
{
    "param1": "aaa",
    "param2": 123,
    "param3": {
        "param3_1": "bbb",
        "param3_2": 456
    }
}
```
### 请求示例
```json
{
  "status": 1,
  "dependencies": [
    {
      "name": "demo-app1",
      "id": "iqtxycne"
    },
    {
      "name": "demo-app1",
      "location": "https://www.huanqiu.com"
    }
  ],
  "userconfigs": {
    "param1": "aaa",
    "param2": 123,
    "param3": {
      "param3_1": "bbb",
      "param3_2": 456
    }
  }
}
```
### 返回值
```json
{
    "code": 0,
    "result": "正在部署中"
}
```

<a name="删除实例"></a>
## 删除实例
### 请求语法
```
DELETE /app/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id|应用实例 id|无|是|
### 返回值
```json
{
    "code": 0,
    "result": "删除成功"
}
```

<a name="获取节点地址"></a>
## 获取节点地址
显示所有节点的IP地址(仅能显示此节点网卡上绑定的IP地址)

### 请求语法
```
GET /cluster/addrs HTTP/1.1
```
### 请求参数
无

### 返回值
```json
{
    "code": 0,
    "result": [
        {
            "name": "master1",
            "addrs": [
              "192.168.0.1",
              "192.168.0.2",
              "192.168.0.3"
            ]
        },
        {
            "name": "salve1",
            "addrs": [
              "192.168.0.4"
            ]
        },
        {
            "name": "salve2",
            "addrs": [
              "192.168.0.5",
              "192.168.0.6"
            ]
        }
    ]
}
```

<a name="获取集群根域"></a>
## 获取集群根域

### 请求语法
```
GET /cluster/domain HTTP/1.1
```
### 请求参数
无

### 返回值
```json
{
    "code": 0,
    "result": "example.com"
}
```

<a name="设置集群根域"></a>
## 设置集群根域

### 请求语法
```
PUT /cluster/domain HTTP/1.1
```
### 请求参数
|名称|说明|默认值|是否必填|
|---|---|---|---|
|domain|绑定到此集群的域名|无|是|
#### 请求参数示例
```json
{
    "domain": "abc.com"
}
```

### 返回值
```json
{
    "code": 0,
    "result": {
      "status": 3,
      "message": "成功"
    }
}
```

`result.status` 为设置根域后的状态码, 数字类型, 具体意义见下表
`result.message` 为当前的状态信息, 字符串,  可直接显示在网页

|  status   | 意义  |
|  ----  | ----  |
| 0  | 检测域名的解析失败 |
| 1  | 检测域名的解析成功, 保存失败 |
| 2  | 检测域名的解析成功, 保存成功 |


<a name="设置工作负载源"></a>
## 设置工作负载源

### 请求语法
```
PUT /cluster/mirror HTTP/1.1
```
### 请求参数
|名称|说明|默认值|是否必填|
|---|---|---|---|
|mirror|作负载源|无|是|
#### 请求参数示例
```json
{
    "mirror": "https://github.com/xxx.git"
}
```

### 返回值
```json
{
    "code": 0,
    "result": "设置成功"
}
```

<a name="查询工作负载源"></a>
## 查询工作负载源

### 请求语法
```
GET /cluster/mirror HTTP/1.1
```
### 请求参数
无

### 返回值
```json
{
    "code": 0,
    "result": "https://github.com/xxx.git"
}
```

<a name="流水线接口"></a>
## 流水线接口

### 请求语法
```
PUT /deployment/<id> HTTP/1.1
Content-Type: multipart/form-data; 
```
### 请求参数

以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id| 实例主键 |无|是|

以下参数为BODY参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|manifest|应用描述文件|无|是|


### 返回值
```json
{
    "code": 0,
    "result": "部署成功"
}
```


<a name="Trait列表"></a>
## Trait列表
### 请求语法
```
GET /trait?limit=<limit>&offset=<offset> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|offset| |0|否|
|limit|  |10|否|

### 返回值
```json
{
  "code": 0,
  "result": {
    "rows": [
      {
        "pk": 1,
        "name": "ingress",
        "apiVersion": "aam.globalsphare.com/v1alpha1",
        "value": "具体定义",
        "type": 0,
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      }
    ],
    "total": 1
  }
}
```


<a name="WorkloadType列表"></a>
## WorkloadType列表
### 请求语法
```
GET /workload/type?limit=<limit>&offset=<offset> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|offset| |0|否|
|limit|  |10|否|

### 返回值
```json
{
  "code": 0,
  "result": {
    "rows": [
      {
        "pk": 1,
        "name": "worker",
        "apiVersion": "aam.globalsphare.com/v1alpha1",
        "value": "具体定义",
        "type": 0,
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      }
    ],
    "total": 1
  }
}
```


<a name="WorkloadVendor列表"></a>
## WorkloadVendor列表
### 请求语法
```
GET /workload/vendor?limit=<limit>&offset=<offset> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|offset| |0|否|
|limit|  |10|否|

### 返回值
```json
{
  "code": 0,
  "result": {
    "rows": [
      {
        "pk": 1,
        "name": "webservice",
        "apiVersion": "aam.globalsphare.com/v1alpha1",
        "value": "具体定义",
        "type": 0,
        "created_at": "2021-10-23T06:49:51.498Z",
        "updated_at": "2021-10-23T06:49:51.498Z"
      }
    ],
    "total": 1
  }
}
```

<a name="修改Trait"></a>
## 修改Trait
### 请求语法
```
PUT /trait/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id|主键|无|是|

以下参数为BODY参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|name|Trait名称 |无|是|
|apiVersion| apiVersion |无|是|
|value| 具体定义 |无|是|
|type| 类型, 0系统内置不可删除 1可删除|0|无|

### 返回值
```json
{
    "code": 0,
    "result": "修改成功"
}
```

<a name="修改WorkloadType"></a>
## 修改WorkloadType
### 请求语法
```
PUT /workload/type/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id|主键|无|是|

以下参数为BODY参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|name|名称 |无|是|
|apiVersion| apiVersion |无|是|
|value| 具体定义 |无|是|
|type| 类型, 0系统内置不可删除 1可删除|0|无|

### 返回值
```json
{
    "code": 0,
    "result": "修改成功"
}
```


<a name="修改WorkloadVendor"></a>
## 修改WorkloadVendor
### 请求语法
```
PUT /workload/vendor/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id|主键|无|是|

以下参数为BODY参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|name|名称 |无|是|
|apiVersion| apiVersion |无|是|
|value| 具体定义 |无|是|
|type| 类型, 0系统内置不可删除 1可删除|0|无|

### 返回值
```json
{
    "code": 0,
    "result": "修改成功"
}
```

<a name="删除Trait"></a>
## 删除Trait
### 请求语法
```
DELETE /trait/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id|主键|无|是|
### 返回值
```json
{
    "code": 0,
    "result": "删除成功"
}
```

<a name="删除WorkloadType"></a>
## 删除WorkloadType
### 请求语法
```
DELETE /workload/type/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id| 主键|无|是|
### 返回值
```json
{
    "code": 0,
    "result": "删除成功"
}
```

<a name="删除WorkloadVendor"></a>
## 删除WorkloadVendor
### 请求语法
```
DELETE /workload/vendor/<id> HTTP/1.1
```
### 请求参数
以下参数为URL PATH参数

|名称|说明|默认值|是否必填|
|---|---|---|---|
|id| 主键|无|是|
### 返回值
```json
{
    "code": 0,
    "result": "删除成功"
}
```