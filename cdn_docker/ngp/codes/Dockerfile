FROM my-ngp-env

ENV BASE_DIR /usr/docker/files

## 1. copy files
WORKDIR ${BASE_DIR}
COPY . .

## 2. uwsgi
RUN mkdir -p /etc/uwsgi/vassals/ && \
    mkdir -p /var/uwsgi/ && \
    ln -s ${BASE_DIR}/uwsgi_aurora.ini /etc/uwsgi/vassals/ && \
    ln -s ${BASE_DIR}/uwsgi_spectrum.ini /etc/uwsgi/vassals/ && \
    mkdir -p /var/log/uwsgi/

## 3. nginx
RUN cp ${BASE_DIR}/nginx.conf /etc/nginx/nginx.conf && \
    ln -s ${BASE_DIR}/ngp.conf /etc/nginx/conf.d/ && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
	ln -sf /dev/stderr /var/log/nginx/error.log

## 4. supervisor
RUN ln -s ${BASE_DIR}/supervisor.conf /etc/supervisor/conf.d/

RUN mkdir -p /usr/local/cdnet/logs/spectrum_api/

RUN echo "alias rp='python /opt/ngp/Portal/aurora_fe/manage.py runserver 0.0.0.0:8090'" >> ~/.bashrc && \
    echo "alias rs='python /opt/ngp/spectrum-api/spectrum_api/manage.py runserver 0.0.0.0:8094'" >> ~/.bashrc

EXPOSE 80 443

CMD ["supervisord"]
