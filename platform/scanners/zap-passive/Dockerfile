FROM ghcr.io/zaproxy/zaproxy:weekly

USER root

# The passive runner is headless. Remove the bundled Webswing GUI stack (and
# its unused Jetty server) and install current distribution security fixes.
RUN apt-get update \
    && apt-get install --only-upgrade -y linux-libc-dev \
    && rm -rf /var/lib/apt/lists/* /zap/webswing /zap/zap-webswing.sh

COPY cypheryn-zap-passive /usr/local/bin/cypheryn-zap-passive
COPY cypheryn-zap-active /usr/local/bin/cypheryn-zap-active
RUN chmod 0555 /usr/local/bin/cypheryn-zap-passive /usr/local/bin/cypheryn-zap-active
USER zap
ENTRYPOINT []
CMD ["cypheryn-zap-passive"]
