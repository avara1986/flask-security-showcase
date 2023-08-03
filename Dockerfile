FROM python:3.10

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
ADD requirements.txt $APP_HOME/requirements.txt
WORKDIR $APP_HOME
RUN set -ex ;\
    ls -la ;\
    pwd ;\
    pip install -r $APP_HOME/requirements.txt ;
RUN pip install gevent gunicorn
ADD . $APP_HOME

ENV DD_TRACE_AGENT_URL=http://ddagent:8126
ENV DD_API_KEY=$DD_API_KEY
ENV DD_SERVICE=albertovara_service_15
ENV DD_ENV=staging
ENV PATH=$PATH:$APP_HOME
ENV PYTHONPATH=$PYTHONPATH:$APP_HOME

RUN pip install git+https://github.com/DataDog/dd-trace-py@1.x#egg=ddtrace

EXPOSE 8000

CMD ["ddtrace-run", "gunicorn", "--workers", "1", "--log-level", "INFO", "--bind", "0.0.0.0:8000", "app:app"]
