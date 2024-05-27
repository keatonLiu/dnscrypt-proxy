$env:GOOS="linux"
go build -o dnscrypt .\dnscrypt-proxy
scp .\dnscrypt ubuntu@h.xtt.asia:/home/ubuntu/odns-probe/dnscrypt
