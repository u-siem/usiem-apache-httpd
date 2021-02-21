FROM owasp/modsecurity:3-apache
COPY ./public-html/ /usr/local/apache2/htdocs/
COPY ./modsecurity.conf /etc/modsecurity.d/modsecurity.conf
COPY ./httpd.conf /usr/local/apache2/conf/httpd.conf
RUN git clone https://github.com/coreruleset/coreruleset.git /usr/local/apache2/coreruleset
COPY ./crs-setup.conf /usr/local/apache2/coreruleset/crs-setup.conf