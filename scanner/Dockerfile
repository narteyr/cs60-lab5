FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    nmap iproute2 iputils-ping dnsutils curl netcat-traditional bash \
    python3 python3-venv python3-pip net-tools \
    python3-scapy tcpdump \
 && rm -rf /var/lib/apt/lists/*


RUN ln -s /usr/bin/python3 /usr/local/bin/python


RUN printf 'if [ -n "$FRIENDLY_NAME" ]; then export PS1="${FRIENDLY_NAME}:\\w\\$ "; echo "Welcome to $FRIENDLY_NAME"; fi\n' \
  > /etc/profile.d/friendly_name.sh

WORKDIR /lab
CMD ["sleep", "infinity"]

