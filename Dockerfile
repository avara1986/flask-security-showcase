FROM python:3.11.6

RUN set -ex ;\
    apt-get update ;\
    apt-get install -y --no-install-recommends python3 curl make git build-essential ;\
# pip shipped with Debian Buster does not support manylinux2020
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=947069
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py ;\
    python3 get-pip.py ;

ENV PYTHONUNBUFFERED=1 APP_HOME=/src/
ENV DATABASE_DIR=database
ENV PYMS_CONFIGMAP_FILE="$APP_HOME"config-docker.yml
RUN mkdir $APP_HOME && adduser -S -D -H python
ADD requirements.txt ${APP_HOME}requirements.txt
WORKDIR $APP_HOME
RUN pip install -U pip
RUN pip install uwsgi
RUN set -ex ;\
    ls -la ;\
    pwd ;\
    pip install -r ${APP_HOME}requirements.txt ;
RUN pip install gevent gunicorn
ADD . $APP_HOME

ENV DD_TRACE_AGENT_URL=http://ddagent:8126
ENV DD_API_KEY=$DD_API_KEY
ENV DD_SERVICE=albertovara_service_15
ENV DD_SERVICE=albertovara_service_iast_leak_11
ENV DD_ENV=staging
ENV DD_TRACE_DEBUG=true
ENV DD_APPSEC_ENABLE=true
ENV DD_IAST_ENABLED=1
ENV PATH=$PATH:$APP_HOME
ENV PYTHONPATH=$PYTHONPATH:$APP_HOME

ENV DD_TRACE_SAMPLE_RATE=1.0
ENV DD_IAST_REQUEST_SAMPLING=100.0
ENV _DD_APPSEC_DEDUPLICATION_ENABLED=false

RUN pip install git+https://github.com/DataDog/dd-trace-py@avara1986/APPSEC-12346-iast_py311_leak#egg=ddtrace

EXPOSE 8000

CMD ["ddtrace-run", "gunicorn", "--workers", "1", "--log-level", "INFO", "--bind", "0.0.0.0:8000", "app:app"]
# CMD ["ddtrace-run", "uwsgi", "--http", "0.0.0.0:8000", "--enable-threads", "--module", "app:app"]
