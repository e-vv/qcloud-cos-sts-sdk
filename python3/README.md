### 获取 SDK

[Python SDK 下载>>](https://github.com/tencentyun/tac-storage-sts-sdk)

### 说明
该SDK是在原python2的文档上修改，使其可以在python3环境运行。使用方式和python2的sdk相同。

### 查看示例

请查看 `sts_demo.py` 文件，里面描述了如何调用SDK。

### 使用方法

拷贝 `sts.py` 文件到您的 python 工程中，调用代码如下：

```
from sts import Sts

config = {
	# 临时密钥有效时长，单位是秒，如果没有设置，默认是30分钟
	'duration_in_seconds': 1800,
	# 您的secret id
	'secret_id': 'xxx',
	# 您的secret key
	'secret_key': 'xxx',
}

sts = Sts(config)
response = sts.get_credential()
json_content = response.content
```

### 返回结果

成功的话，可以拿到包含密钥的 JSON 文本：

```
{"code":0,"message":"","codeDesc":"Success","data":{"credentials":{"sessionToken":"2a0c0ead3e6b8eed9608899eb74f2458812208ab30001","tmpSecretId":"AKIDBSrMaeFD0ZAECKuBzohnjAhJ53XNCE2F","tmpSecretKey":"UC7YjMrIlcuFgoWGwnrHwsMBrQrpUwYI"},"expiredTime":1526288317}}
```


