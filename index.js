 /**
 * @author Chenzhyc
 * @description 分站express引用
 */

const crypto = require('crypto');
const request = require('request');

/**
 * MD5 hash
 * @param  {string} str [string to be hashed]
 * @return {string}     [hashed string with hex]
 */
function md5(str) {
    const hash = crypto.createHash('md5');
    return hash.update(str).digest('hex');
}

/**
 * check if a string is format of JSON
 * @param  {string}  str [description]
 * @return {Boolean}     [description]
 */
function isJsonString(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}

/**
 * decode base64 string
 * @param  {string} str [string with base64 encoded]
 * @return {string}     [original string]
 */
function base64Decode(str) {
    if (typeof str !== 'string') {
        return null;
    }

    return new Buffer(str, 'base64').toString();
}

/**
 * 校验sessionId
 * @param  {string} ssoUrl  [单点认证中心url]
 * @param  {string} siteUrl [分站url]
 * @param  {string} webserviceUrl [java api url]
 * @return {function}         [在express中使用]
 */
exports.checkSid = function(ssoUrl, siteUrl, webserviceUrl) {
    return function(req, res, next) {
        //如果不存在ycsid，则需重新登录
        if (!req.cookies.ycsid) {
            res.redirect(`${ssoUrl}?redirectUrl=${siteUrl}&errorMsg=NoSID`);
            return;
        }else if (!req.cookies.userId){ // 如果cookie中不存在userId，则也需要重新登录
            res.redirect(`${ssoUrl}?redirectUrl=${siteUrl}&errorMsg=NoUserId`);
            return;
        }else {
            //校验ycsid合法性
            const params = {
                userName: req.cookies.userName,
                password: '',
                sessionId: req.cookies.ycsid,
                ips: [ req.cookies.deviceId ],
                expiresIn: 30 * 24 * 60 * 60,
                country: req.cookies[md5('country')] ? base64Decode(req.cookies[md5('country')]) : '',
                province: '',
                city: req.cookies[md5('city')] ? base64Decode(req.cookies[md5('city')]) : '',
                lat: req.cookies[md5('lat')] ? base64Decode(req.cookies[md5('lat')]) : '',
                lon: req.cookies[md5('lon')] ? base64Decode(req.cookies[md5('lon')]) : '',
                district: req.cookies[md5('city')] ? base64Decode(req.cookies[md5('city')]) : '',
                userAgent: req.get('User-Agent'),
                redirectUrl: siteUrl,
                captchaId: '',
                captcha: ''
            }

            const reqBody = {
                header: {
                    deviceId: req.cookies.deviceId ? req.cookies.deviceId : '',
                    clientType: req.cookies.clientType ? req.cookies.clientType : 'web',
                    clientVersion: req.cookies.clientVersion ? req.cookies.clientVersion : '',
                    clientId: req.cookies.clientId ? req.cookies.clientId : ''
                },
                body: {
                    action: 'getTicket',
                    requestParam: params
                }
            };

            request.post({ url: webserviceUrl, form: JSON.stringify(reqBody) }, function(err, response, body){

                if (isJsonString(body) == false) {
                    res.json({
                        code: -1,
                        status: 500,
                        msg:'接口请求失败，请检查请求路径和参数，返回非json文本',
                        resbody: body,
                        err: err
                    });
                    return;
                }
                const ret = JSON.parse(body);
                //如果校验成功，则继续
                if (ret.code == 0) {
                    next();
                }else {
                    //校验失败需重新登录
                    res.redirect(`${ssoUrl}?redirectUrl=${siteUrl}&errorMsg=${body}`);
                    return;
                }
            });
        }
    }
};

/**
 * 通用转发中间件
 * @param  {string} webserviceUrl Java Api url
 * @return {function}              used in express
 */
exports.forwardMiddleWare = function (webserviceUrl) {
    return function(req, res, next) {
        //将ycsid替换为userToken
        const b = {};
        Object.assign(b, req.body);
        b.body.requestParam.userToken = req.cookies.ycsid;

        request.post({ url: webserviceUrl , form: JSON.stringify(b) }, function(err, response, body){

            if (isJsonString(body) == false) {
                res.json({
                    code: -1,
                    status: 500,
                    msg:'接口请求失败，请检查请求路径和参数，返回非json文本',
                    resbody: body,
                    err: err
                });
                return;
            }

            res.status(200).send(body);
            return;
        });
    }
};

/**
 * 通过授权码即ticket 换取共享的sessionId
 * @param  {string} webserviceUrl [Java Api url of sso]
 * @param  {number} maxAge  [cookie中的maxAge]
 * @return {function}               [used in express]
 */
exports.checkTicket = function(webserviceUrl, maxAge, siteUrl) {
    return function(req, res, next) {
        //如果没有传ticket
        if (!req.query.ticket || !req.query.deviceId) {
            res.json({
                code: -1,
                msg:'参数错误',
            });
            return;
        }

        const params = {
            ticket: req.query.ticket,
            ips: [ req.query.deviceId ],
            expiresIn: 30 * 24 * 60 * 60,
            country: base64Decode(req.cookies[md5('country')] ? req.cookies[md5('country')] : ''),
            province: '',
            city: base64Decode(req.cookies[md5('city')] ? req.cookies[md5('city')] : ''),
            lat: base64Decode(req.cookies[md5('lat')] ? req.cookies[md5('lat')] : ''),
            lon: base64Decode(req.cookies[md5('lon')] ? req.cookies[md5('lon')] : ''),
            district: base64Decode(req.cookies[md5('city')] ? req.cookies[md5('city')] : ''),
            userAgent: req.get('User-Agent'),
            redirectUrl: siteUrl
        };

        const reqBody = {
            header: {
                deviceId: req.cookies.deviceId ? req.cookies.deviceId : '',
                clientType: req.cookies.clientType ? req.cookies.clientType : 'web',
                clientVersion: req.cookies.clientVersion ? req.cookies.clientVersion : '',
                clientId: req.cookies.clientId ? req.cookies.clientId : ''
            },
            body: {
                action: 'getSid',
                requestParam: params
            }
        };

        request.post({ url: webserviceUrl, form: JSON.stringify(reqBody) }, function(err, response, body){
            if (isJsonString(body) == false) {
                res.json({
                    code: -1,
                    status: 500,
                    msg:'接口请求失败，请检查请求路径和参数，返回非json文本',
                    resbody: body,
                    err: err
                });
                return;
            }

            const ret = JSON.parse(body);

            if (ret.code == 0 && ret.sessionId) {
                //如果存在remember，则将sid存储时效为一个月，否则只存在于session中
                if (req.query.remember === 'true') {
                    res.cookie('ycsid', ret.sessionId, { maxAge: maxAge, httpOnly: true });
                }else{
                    res.cookie('ycsid', ret.sessionId, { httpOnly: true });
                }
                res.cookie('userId', req.query.userId, { maxAge: maxAge });
                res.cookie('userName', req.query.userName, { maxAge: maxAge });
                res.cookie('userType', req.query.userType, { maxAge: maxAge });
                res.cookie('imgLink', req.query.imgLink, { maxAge: maxAge });
                res.cookie('remember', req.query.remember, { maxAge: maxAge });
                res.status(200).send('ok');
                return;
            }else {
                //换票失败需重新登录
                res.json({
                    code: ret.code,
                    msg: ret.msg,
                });

                return;
            }
        });
    }
};
