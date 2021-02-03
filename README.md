## 非对称加密

**STEP：**

* $encry = new EasyWTEncry(?$salt=string, ?$ipaddr=string)
* $encry->encryption($encry=[str|arr|obj], ?$expire_int=int) 加密
* $encry->decryption($decry=string, ?$salt=string, ?ipaddr=string) 解密
* $encry->update_expire($decry=string, ?$expire_date=string) 更新失效日期
