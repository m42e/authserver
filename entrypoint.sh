#!/bin/bash
set -e

if [ "$1" = 'generate_config' ]; then
    rm config.cfg
    shift
fi

if [ ! -f "config.cfg" ]; then
    secret=$(openssl rand -base64 32)
    cat > config.cfg <<-EOF
SECRET_KEY="$secret"
DB_PATH="sqlite:///users.db"
JWT_PRIVATE_KEY="jwtRS256.key"
JWT_PUBLIC_KEY="jwtRS256.key.pub"
EOF
    generate_keys=1
fi

if [ "$1" = 'generate_keys' ]; then
    generate_keys=1
    shift
fi

if [ "x${generate_keys}x" == "x1x" ]; then
    ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key -N ''
    # Don't add passphrase
    openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
fi

exec python /app/app.py "$@"
