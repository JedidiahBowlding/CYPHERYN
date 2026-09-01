FROM drwetter/testssl.sh:3.2

USER root
COPY cypheryn-testssl /usr/local/bin/cypheryn-testssl
RUN chmod 0555 /usr/local/bin/cypheryn-testssl
USER testssl
ENTRYPOINT []
CMD ["cypheryn-testssl"]
