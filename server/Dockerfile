FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    nginx \
    rsyslog \
    nftables \
    iproute2 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /opt/soar /reports && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY wazuh_soar_agent.py /opt/soar/wazuh_soar_agent.py
COPY entrypoint.sh /entrypoint.sh
RUN sed -i '1s/^\xEF\xBB\xBF//' /entrypoint.sh && \
    sed -i 's/\r$//' /entrypoint.sh && \
    chmod +x /entrypoint.sh

EXPOSE 22 80
CMD ["/bin/bash", "/entrypoint.sh"]
