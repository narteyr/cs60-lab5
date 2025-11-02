FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*

COPY portfarm /usr/local/bin/portfarm
RUN chmod +x /usr/local/bin/portfarm

CMD ["/usr/local/bin/portfarm"]
