import logging
import os
import sqlite3
import subprocess

from flask import request, Flask

from ddtrace.appsec.iast._taint_tracking import get_tainted_ranges
from ddtrace.appsec.iast._taint_tracking import is_pyobject_tainted
from ddtrace.internal.service import ServiceStatus
from ddtrace.internal.telemetry import telemetry_writer

logging.basicConfig(level=logging.DEBUG)
LOGS_FILE = os.path.dirname(__file__)


def create_app():
    app = Flask(__name__)

    @app.route('/')
    def helthcheck():
        return "OK"

    def pt_open(origin_string):
        print("pt_open!!!!!!!!!!")
        print(is_pyobject_tainted(origin_string))
        print(get_tainted_ranges(origin_string))
        p = "1" + origin_string
        print("p!!!!!!!!!!!!!!")
        print(is_pyobject_tainted(p))
        print(get_tainted_ranges(p))
        m = open(origin_string)
        return m.read()

    @app.route('/source_header/vuln_path_traversal')
    def path_traversal_header():
        file_path = request.headers.get("pt-file", "")
        result = "NO_FILE"

        if file_path:
            # result = pt_open2(file_path)
            m = open(file_path)
            result = m.read()
        return {"result": result, "tainted": is_pyobject_tainted(file_path),
                "ranges": str(get_tainted_ranges(file_path))}

    @app.route('/source_queryparam/vuln_path_traversal', methods=['GET'])
    def path_traversal_get():
        file_path = request.args.get("pt_file")
        result = "NO_FILE"
        if file_path:
            # result = pt_open2(file_path)
            m = open(file_path)
            result = m.read()
        return {"result": result, "tainted": is_pyobject_tainted(file_path),
                "ranges": str(get_tainted_ranges(file_path))}

    @app.route('/source_queryparam/vuln_sqli', methods=['GET'])
    def sqli_get():
        table = request.args.get("table")
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute("CREATE TABLE students (name TEXT, addr TEXT, city TEXT, pin TEXT)")
        cur.execute("SELECT 1 FROM " + table)
        rows = cur.fetchall()
        return {"result": rows, "tainted": is_pyobject_tainted(table),
                "ranges": str(get_tainted_ranges(table))}

    @app.route('/source_body/vuln_sqli', methods=['POST'])
    def sqli_post():
        password_u = request.form.get("password")
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute("CREATE TABLE students (id TEXT, password TEXT, city TEXT, pin TEXT)")
        cur.execute("SELECT 1 FROM students WHERE password = '" + password_u + "'")
        rows = cur.fetchall()
        return {"result": rows, "tainted": is_pyobject_tainted(password_u),
                "ranges": str(get_tainted_ranges(password_u))}

    @app.route('/source_header/vuln_sqli')
    def sqli_header():
        password_u = request.headers.get("password", "")
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute("CREATE TABLE students (id TEXT, password TEXT, city TEXT, pin TEXT)")
        cur.execute("SELECT 1 FROM students WHERE password = '" + password_u + "'")
        rows = cur.fetchall()
        return {"result": rows, "tainted": is_pyobject_tainted(password_u),
                "ranges": str(get_tainted_ranges(password_u))}

    @app.route("/source_pathparam/vuln_sqli/<password>")
    def sqli_pathparam(password):
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute("CREATE TABLE students (id TEXT, password TEXT, city TEXT, pin TEXT)")
        cur.execute("SELECT 1 FROM students WHERE password = '" + password + "'")
        rows = cur.fetchall()
        return {"result": rows, "tainted": is_pyobject_tainted(password),
                "ranges": str(get_tainted_ranges(password))}

    @app.route("/source_pathparam/vuln_cmdi/<filename>")
    def cmdi_pathparam(filename):
        subp = subprocess.Popen(args=["ls", "-la", filename])
        subp.communicate()
        subp.wait()
        return {"result": filename, "tainted": is_pyobject_tainted(filename),
                "ranges": str(get_tainted_ranges(filename))}

    @app.route('/source_queryparam/vuln_cmdi', methods=['GET'])
    def cmdi_get():
        filename = request.args.get("filename")
        subp = subprocess.Popen(args=["ls", "-la", filename])
        subp.communicate()
        subp.wait()
        return {"result": filename, "tainted": is_pyobject_tainted(filename),
                "ranges": str(get_tainted_ranges(filename))}

    @app.route("/metrics")
    def metrics_view():
        # telemetry_metrics_writer.add_count_metric(
        #         TELEMETRY_NAMESPACE_TAG_TRACER,
        #         "test_metric",
        #         1.0,
        #     )
        namespace_metrics = telemetry_writer._namespace.get()
        metrics = [m.to_dict() for payload_type, namespaces in namespace_metrics.items() for namespace, metrics in
                   namespaces.items() for m in metrics.values()]
        return {
                   "telemetry_metrics_writer_running": telemetry_writer.status == ServiceStatus.RUNNING,
                   "telemetry_metrics_writer_worker": telemetry_writer._worker is not None,
                   "telemetry_metrics_writer_queue": metrics
               }, 200

    @app.route('/normal')
    def normal():
        return "OK"

    @app.route('/attack')
    def attack():
        return "OK"

    @app.route('/block')
    def block():
        return "OK"

    return app
