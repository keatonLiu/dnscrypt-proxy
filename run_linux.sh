export GOOS=linux
go build -o dnscrypt .\dnscrypt-proxy
.\dnscrypt --config .\dnscrypt-proxy.toml