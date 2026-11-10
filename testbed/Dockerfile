FROM httpd:2.4

# Força o uso do MPM prefork (um processo por conexão, mais fácil de esgotar
# que o event/worker, que são mais resilientes a esse tipo de ataque)
RUN sed -i 's/^LoadModule mpm_event_module/#LoadModule mpm_event_module/' /usr/local/apache2/conf/httpd.conf \
    && sed -i 's/^#LoadModule mpm_prefork_module/LoadModule mpm_prefork_module/' /usr/local/apache2/conf/httpd.conf

# Limites baixos de workers + timeout curto: faz o esgotamento de conexões
# acontecer rápido e de forma clara nos pcaps e nos logs
RUN cat >> /usr/local/apache2/conf/httpd.conf <<'EOF'

<IfModule mpm_prefork_module>
    StartServers         5
    MinSpareServers      3
    MaxSpareServers      5
    MaxRequestWorkers    20
    MaxConnectionsPerChild 0
</IfModule>

Timeout 30
EOF

# Uma página simples só pra servir de alvo
RUN echo "<html><body><h1>Testbed Apache - Slowloris P1</h1></body></html>" > /usr/local/apache2/htdocs/index.html

EXPOSE 80
