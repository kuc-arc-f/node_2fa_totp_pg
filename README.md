# node_2fa_totp_pg

 Version: 0.9.1

 Author  : 

 date    : 2026/10/31
 
 update  :

***
### Summary

node.js , authrize 2FA TOTP PostgreSQL

* PostgreSQL Database
* phone App :Google Authenticator use
* otplib
* node22
* Linux

***

* .env
```
PORT=3000
DATABASE_URL=postgres://root:admin@localhost:5432/mydb
SESSION_SECRET=ここに長いランダム文字列
# 32バイト(hex 64文字): node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
TOTP_ENC_KEY=
APP_NAME=DemoApp
NODE_ENV=development

```

***
* Table: ./schema.sql

***
* node start
```
npm install
npm run start
```

***
### version
* V_0_9_1: new

***
### blog

https://zenn.dev/knaka0209/scraps/33bbad05d2a9c7

