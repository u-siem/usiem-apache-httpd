FROM owasp/modsecurity:2-apache
COPY ./public-html/ /usr/local/apache2/htdocs/
COPY ./modsecurity.conf /etc/modsecurity.d/modsecurity.conf
COPY ./httpd.conf /usr/local/apache2/conf/httpd.conf
RUN apt update && apt install -y ca-certificates git && git clone https://github.com/coreruleset/coreruleset.git /usr/local/apache2/coreruleset
COPY ./crs-setup.conf /usr/local/apache2/coreruleset/crs-setup.conf
COPY ./entrypoint.sh /etc/entrypoint.sh
RUN chmod +x /etc/entrypoint.sh

CMD ["/etc/entrypoint.sh"]