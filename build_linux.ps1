$env:GOOS="linux"
go build -o dnscrypt .\dnscrypt-proxy
scp .\dnscrypt ubuntu@u.xxt.asia:/home/ubuntu/odns-probe/dnscrypt
