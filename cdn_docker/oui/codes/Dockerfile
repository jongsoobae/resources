FROM oui-env

ENV BASE_DIR /usr/docker/files

## 1. copy files
WORKDIR ${BASE_DIR}
COPY . .

## 2. uwsgi
RUN mkdir -p /etc/uwsgi/vassals/ && \
    mkdir -p /var/uwsgi/ && \
    ln -s ${BASE_DIR}/uwsgi_oui.ini /etc/uwsgi/vassals/ && \
    ln -s ${BASE_DIR}/uwsgi_api.ini /etc/uwsgi/vassals/ && \
    ln -s ${BASE_DIR}/uwsgi_cui.ini /etc/uwsgi/vassals/ && \
    mkdir -p /var/log/uwsgi/

## 3. nginx
RUN cp ${BASE_DIR}/nginx.conf /etc/nginx/nginx.conf && \
    ln -s ${BASE_DIR}/pe_portal.conf /etc/nginx/conf.d/ && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
	ln -sf /dev/stderr /var/log/nginx/error.log

## 4. supervisor
RUN ln -s ${BASE_DIR}/supervisor.conf /etc/supervisor/conf.d/

## 5. etc
RUN echo "export PYTHONPATH=/opt/cdn/ui/prod" >> ~/.bashrc && \
    echo "alias ro='python /opt/cdn/ui/prod/ui/oui/manage.py runserver 0.0.0.0:8080'" >> ~/.bashrc && \
    echo "alias rc='python /opt/cdn/ui/prod/ui/cui/manage.py runserver 0.0.0.0:8081'" >> ~/.bashrc && \
    echo "alias ra='python /opt/cdn/ui/prod/api/manage.py runserver 0.0.0.0:8082'" >> ~/.bashrc

EXPOSE 80 443

CMD ["supervisord"]
