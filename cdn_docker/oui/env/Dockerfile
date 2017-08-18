FROM ubuntu:16.04

ENV BASE_DIR /usr/docker/files

WORKDIR ${BASE_DIR}
COPY . .

RUN cd /etc/apt && \
    sed -i 's/archive.ubuntu.com/ftp.daum.net/g' sources.list

RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
         vim \
         build-essential \ 
         python-dev \
         ca-certificates \
         nginx \
         supervisor \
         python-pip \
         python-mysqldb \
         python-m2crypto \
         python-pycurl \
         python-zsi \
         memcached \
         python-memcache \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip && pip install -U setuptools &&  pip install -r requirements.txt

CMD ["/bin/bash"]
