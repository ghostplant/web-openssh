FROM alpine:3.4
MAINTAINER CUI Wei <ghostplant@qq.com>

RUN apk --update add nginx && rm -rf /var/cache/apk
ADD static /opt/static
ADD wsh-run /opt/wsh-run
ADD www.cfg.in /opt/www.cfg.in
ADD module/ngx_http_webshell_module.so /opt/module/ngx_http_webshell_module.so

EXPOSE 8000/tcp
CMD "/opt/wsh-run"
