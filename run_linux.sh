export GOOS=linux
echo "Building for $GOOS"
go build -o dnscrypt ./dnscrypt-proxy
echo "Running dnscrypt"
./dnscrypt --config ./dnscrypt-proxy.toml
