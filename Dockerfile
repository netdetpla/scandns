FROM golang:latest 

ADD ["sources.list", "/etc/apt/"]

RUN apt update \
    && apt -y install python3 wget alien zmap net-tools git gcc git make libpcap-dev \
    && cd / \
    && git clone https://github.com/robertdavidgraham/masscan \
    && cd masscan \
    && make \
    && cd / \
    && wget https://nmap.org/dist/nmap-7.70-1.x86_64.rpm \
    && alien nmap*.rpm \
    && dpkg --install nmap*.deb \
    && mkdir -p $GOPATH/src/golang.org/x/ \
    && cd $GOPATH/src/golang.org/x/ \
    && git clone https://github.com/golang/sys.git \
    && git clone https://github.com/golang/crypto.git \
    && go install golang.org/x/sys/unix golang.org/x/crypto/ssh/terminal \
    #&& go install sys/unix crypto/ssh/terminal \
    #&& mkdir -p $GOPATH/src/golang/x/ \
    #&& mv sys $GOPATH/src/golang/x/ \
    #&& mv crypto $GOPATH/src/golang/x/ \
    && go get github.com/zmap/zgrab \
    && go get github.com/zmap/zdns/zdns \
    && apt clean

WORKDIR /

ADD ["scandns", "/"]

CMD python3 main.py

