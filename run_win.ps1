$env:GOOS="windows"
go build -o dnscrypt.exe .\dnscrypt-proxy
.\dnscrypt.exe --config .\dnscrypt-proxy\dnscrypt-proxy.toml
