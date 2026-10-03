FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    curl \
    openssh-client \
    sshpass \
    iputils

COPY run_tests.sh /run_tests.sh
RUN sed -i '1s/^\xEF\xBB\xBF//' /run_tests.sh && \
    sed -i 's/\r$//' /run_tests.sh && \
    chmod +x /run_tests.sh

CMD ["/bin/bash", "/run_tests.sh"]
