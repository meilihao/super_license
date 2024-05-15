# README
**不推荐和加密license数据共用同一把rsa key**.

## demo
```bash
$ ./slreq build -e ../sltool/id_rsa.pub.pem # use encrypt
$ ./slreq parse -d ../sltool/id_rsa.pem -n 123456
$ cat req.dat |basenc --base64url -d |hexdump -C
```