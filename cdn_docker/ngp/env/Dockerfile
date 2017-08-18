FROM ubuntu:16.04

ENV BASE_DIR /usr/docker/files

WORKDIR ${BASE_DIR}
COPY . .

#RUN cd /etc/apt && \
#    sed -i 's/archive.ubuntu.com/mirror.premi.st/g' sources.list

RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
         build-essential \ 
         python-dev \
         ca-certificates \
         nginx \
         supervisor \
         memcached \
         python-pip \
         python-mysqldb \
         python-m2crypto \
         python-pycurl \
         python-zsi \
         python-ldap \
         python-svn \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip && \
    pip install -U setuptools && \
    pip install -r requirements.txt && \
    pip uninstall -y celery && \
    pip install celery==3.1

CMD ["/bin/bash"]
