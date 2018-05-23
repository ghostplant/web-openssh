FROM alpine:3.4
MAINTAINER CUI Wei <ghostplant@qq.com>

ENV LANG en_US.UTF-8

RUN apk --update add nginx openssl tmux openssh-client screen && rm -rf /var/cache/apk
ADD static /opt/static
ADD wsh-run /opt/wsh-run
ADD www.cfg.in /opt/www.cfg.in
ADD module/ngx_http_webshell_module.so /opt/module/ngx_http_webshell_module.so

EXPOSE 8080/tcp
CMD "/opt/wsh-run"
