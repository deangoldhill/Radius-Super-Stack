FROM freeradius/freeradius-server:3.2.3-alpine

# Install MariaDB connector, OpenSSL, make, and python3
RUN apk update && apk add --no-cache freeradius-mysql mariadb-connector-c openssl make python3

# Enable the SQL module (force symlink using the true absolute path)
RUN ln -sf /opt/etc/raddb/mods-available/sql /opt/etc/raddb/mods-enabled/sql

# Configure the SQL module
RUN sed -i 's/driver = "rlm_sql_null"/driver = "rlm_sql_mysql"/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/dialect = "sqlite"/dialect = "mysql"/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/.*server = "localhost".*/\tserver = "db"\n\tport = 3306/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/.*login = "radius".*/\tlogin = "radius"/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/.*password = "radpass".*/\tpassword = "radpass"/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/.*radius_db = "radius".*/\tradius_db = "radius"/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/.*read_clients = yes.*/\tread_clients = yes/g' /opt/etc/raddb/mods-available/sql

# Disable TLS requirements in SQL module
RUN sed -i 's/ca_file =/#ca_file =/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/certificate_file =/#certificate_file =/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/private_key_file =/#private_key_file =/g' /opt/etc/raddb/mods-available/sql && \
    sed -i 's/tls_required = yes/tls_required = no/g' /opt/etc/raddb/mods-available/sql

# Enable SQL in the default and inner-tunnel sites
RUN sed -i 's/-sql/sql/g' /opt/etc/raddb/sites-available/default && \
    sed -i 's/-sql/sql/g' /opt/etc/raddb/sites-available/inner-tunnel

# Enable use_tunneled_reply
RUN sed -i 's/^[ \t]*#[ \t]*use_tunneled_reply/\tuse_tunneled_reply/g' /opt/etc/raddb/sites-available/default

# Inject required attributes to outer tunnel securely
RUN sed -i '/post-auth {/a \
    update outer.session-state { \n\
        Tunnel-Type := &reply:Tunnel-Type \n\
        Tunnel-Medium-Type := &reply:Tunnel-Medium-Type \n\
        Tunnel-Private-Group-ID := &reply:Tunnel-Private-Group-ID \n\
        Framed-IP-Address := &reply:Framed-IP-Address \n\
        Acct-Interim-Interval := &reply:Acct-Interim-Interval \n\
        Session-Timeout := &reply:Session-Timeout \n\
        Reply-Message := &reply:Reply-Message \n\
    }' /opt/etc/raddb/sites-available/inner-tunnel

# Pre-configure the 10 year defaults
RUN cd /opt/etc/raddb/certs && \
    sed -i 's/default_days.*= 60/default_days = 3650/g' ca.cnf && \
    sed -i 's/default_days.*= 60/default_days = 3650/g' server.cnf

# Create the Self-Healing Startup Script
# If server.pem is missing, it automatically regenerates all certificates BEFORE starting
RUN echo '#!/bin/sh' > /start.sh && \
    echo 'if [ ! -f /opt/etc/raddb/certs/server.pem ]; then' >> /start.sh && \
    echo '  echo "Certificates missing. Generating default EAP certificates..."' >> /start.sh && \
    echo '  cd /opt/etc/raddb/certs' >> /start.sh && \
    echo '  rm -f *.pem *.der *.csr *.crt *.key *.p12 serial* index.txt*' >> /start.sh && \
    echo '  make all' >> /start.sh && \
    echo '  chown -R radius:radius /opt/etc/raddb/certs/ || true' >> /start.sh && \
    echo 'fi' >> /start.sh && \
    echo 'exec radiusd -f -l stdout' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 1812/udp
EXPOSE 1813/udp

CMD ["/start.sh"]
