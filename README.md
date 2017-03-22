# yc-passport-client
SSO Client Side of Yuechuang

用法:
```js
const yc_pass_client = require('yc-passport-client');
const app = require('express');
...
app.get('/checkTicket', ycpass_client.checkTicket(ssoApiUrl, 30 * 24 * 60 * 60 * 1000, siteUrl));
app.get('*', ycpass_client.checkSid(ssoUrl, siteUrl, javaApiUrl));
...
app.post('/api', ycpass_client.forwardMiddleWare(javaApiUrl));
...
app.listen(app.get('port'), () => {
  ...
});
```
参数说明:
ssoUrl: 登录跳转地址
siteUrl: 分站地址
javaApiUrl: 后台api地址
ssoApiUrl: 单点后台api地址
