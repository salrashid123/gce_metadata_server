FROM debian
RUN apt-get -y update && apt-get install -y bind9  bind9utils bind9-doc curl dnsutils supervisor vim

RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ADD google.internal.db /etc/bind/zones/google.internal.db
ADD named.conf.local /etc/bind/named.conf.local
ADD named.conf.options /etc/bind/named.conf.options
EXPOSE 53

#CMD ["/usr/bin/supervisord"]
ENTRYPOINT ["/usr/sbin/named","-f","-g","-d","1"]

# sudo docker run -t -p 53:53 -p 53:53/udp salrashid123/metadatadns
# nslookup -port=53 metadata.google.internal 127.0.0.1
