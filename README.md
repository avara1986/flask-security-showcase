# Flask Showcase

```shell
export DDTRACE_PY_PATH="~/projects/dd-python/dd-trace-py"
cd $DDTRACE_PY_PATH
docker-compose up -d ddagent
cd - 
export PYTHONPATH=$PYTHONPATH:$DDTRACE_PY_PATH
```

Start with a virtualenv
```shell
pip install -r requirements.txt
export DD_AGENT_PORT=8126
export DD_AGENT_PORT=8126
export DD_API_KEY=$DD_API_KEY
export DD_APPSEC_ENABLED=true
export DD_ENV=sandbox
export DD_PROFILING_ENABLED=true
export DD_SERVICE=alberto.vara-flask
export DD_TRACE_DEBUG=true
export DD_TRACE_STARTUP_LOGS=true
export DD_VERSION=0.1
export PYTHONUNBUFFERED=1
```

```
python app.py --no-reload
python -m ddtrace.commands.ddtrace_run gunicorn -w 1 app:app
uwsgi --http 0.0.0.0:8000 --processes 1 --threads 1 --module app:app  --import=ddtrace.bootstrap.sitecustomize
```