# Authserver

This repository offers a (to be honest a hacky) implementation which allows to use a login using `auth_request` module in nginx.
It enforces two factor authorization or token based `Authorization` header.

## Add User
Run the docker image with `adduser` and `-it`.

## Create a token
Run the docker image with `token <username>`.

## Delete a token
Run the docker image with `token <username> --rm <token>`.


## Run Docker

```sh
docker run -v /var/proj/authserver/data:/home/appuser -p 127.0.0.1:9999:9999/tcp authserver:latest
```


## Nginx Configuration

### authorization protected

```nginx
location ^~ / {
    proxy_pass http://127.0.0.1:5232;
    auth_request /login-validate;
    auth_request_set $auth_user $upstream_http_x_user;
    proxy_set_header     X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Remote-User $auth_user;
    proxy_set_header X-Remote-User $auth_user;
		# Set the header according what you need.
		
}

error_page 401 /error/401.html;

# If the user is not logged in, redirect them to login URL
location = /error/401.html {
  return 302 https://login.d1v3.de/login?fwd=https://$http_host$request_uri;
}


location = /login-validate {
  proxy_pass http://127.0.0.1:9999/auth;
  proxy_pass_request_body off; # no need to send the POST body

  proxy_set_header Content-Length "";
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  auth_request_set $auth_user $upstream_http_x_user;
}
```

### login page

```nginx
location / {
	proxy_pass http://127.0.0.1:9999/;
	proxy_set_header  Host  login.d1v3.de;
	proxy_set_header  X-Forwarded-Proto https;
	if ($scheme != "https") {
		rewrite ^ https://$host$request_uri? permanent;
	}
}
```
