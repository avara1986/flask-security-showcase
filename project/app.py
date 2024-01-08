import json
import logging
import os
import sqlite3
import subprocess
import random
from resource import *
import requests
from flask import request
from flask import Flask
from flask import Response

from ddtrace.internal.service import ServiceStatus
from ddtrace.internal.telemetry import telemetry_writer


from ddtrace.appsec.iast._taint_tracking import get_tainted_ranges
from ddtrace.appsec.iast._taint_tracking import is_pyobject_tainted

logging.basicConfig(level=logging.DEBUG)
LOGS_FILE = os.path.dirname(__file__)


def unsafe_sql_format(query_string, *args, **kwargs):
    # Note that this function should only be used for formatting metadata
    # in a query string. Metadata includes table names, column names and
    # order type.
    return query_string.format(*args, **kwargs)


def create_app():
    app = Flask(__name__)

    @app.route('/')
    def helthcheck():
        return "OK"

    @app.route('/iast/propagation', methods=['POST'])
    def iast_propagation():
        origin_string1 = request.form["string1"]
        tainted_string_2 = request.form["password"]

        if type(origin_string1) is str:
            string1 = str(origin_string1)  # 1 Range
        else:
            string1 = str(origin_string1, encoding="utf-8")  # 1 Range

        if type(tainted_string_2) is str:
            string2 = str(tainted_string_2)  # 1 Range
        else:
            string2 = str(tainted_string_2, encoding="utf-8")  # 1 Range
        string3 = string1 + string2  # 2 Ranges
        string4 = "-".join([string3, string3, string3])  # 6 Ranges
        string5 = string4[0:20]  # 1 Ranges
        string6 = string5.title()
        string7 = string6.upper()
        string8 = "%s_notainted" % string7
        string9 = "notainted_{}".format(string8)

        try:
            # label propagation_memory_check
            m = open("/" + string9 + ".txt")
            _ = m.read()
        except Exception:
            pass

        try:
            # label propagation_memory_check
            m = subprocess.Popen("ls " + string9)
        except Exception:
            pass

        try:
            # label propagation_memory_check
            requests.get("http://" + string9)
        except Exception:
            pass

        _ = random.randint(1, 10)
        # expected = "notainted_HIROOT1234-HIROOT123_notainted"
        # assert string9 == expected, f"Error, string 9 is\n{string9}\nExpected:\n{expected}"
        memory = getrusage(RUSAGE_SELF).ru_maxrss
        resp = Response(json.dumps({"string_result": string9, "tainted": is_pyobject_tainted(string9),
                "ranges": str(get_tainted_ranges(string9)), "memory": memory}))
        resp.set_cookie("insecure", "cookie", secure=False, httponly=False, samesite="None")

        return resp

    @app.route("/iast/propagation3", methods=["GET"])
    def iast_propagation_3():
        """Application Vulnerability Management has 3 key concepts: origins, propagation and sink points (vulnerabilities)
        this view validates some origins, check the propagation of different strings and multiple vulnerabilities
        """
        # Origin 1: string1
        origin_string1 = request.args.get("string1")
        # Origin 2: password
        tainted_string_2 = request.args.get("password")

        string1 = str(origin_string1)  # String with 1 propagation range
        string2 = str(tainted_string_2)  # String with 1 propagation range

        string3 = string1 + string2  # 2 propagation ranges: hiroot1234
        string4 = "-".join([string3, string3, string3])  # 6 propagation ranges: hiroot1234-hiroot1234-hiroot1234
        string5 = string4[0:20]  # 1 propagation range: hiroot1234-hiroot123
        string6 = string5.title()  # 1 propagation range: Hiroot1234-Hiroot123
        string7 = string6.upper()  # 1 propagation range: HIROOT1234-HIROOT123
        string8 = "%s_notainted" % string7  # 1 propagation range: HIROOT1234-HIROOT123_notainted
        string9 = "notainted_{}".format(string8)  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted

        try:
            # Path traversal vulnerability
            m = open("/" + string9 + ".txt")
            _ = m.read()
        except Exception:
            pass

        try:
            # Command Injection vulnerability
            _ = subprocess.Popen("ls " + string9)
        except Exception:
            pass

        try:
            # SSRF vulnerability
            requests.get("http://" + string9)
        except Exception:
            pass

            # Weak Randomness vulnerability
        _ = random.randint(1, 10)

        # validates default output and IAST output
        # expected = "notainted_HIROOT1234-HHIROOT123ROOT123_notainted"
        # expected = "notainted_HIROOT1234-HIROOT123_notainted"
        # assert string9 == expected, f"Error, string 9 is\n{string9}\nExpected:\n{expected}"

        # Insecure Cookie vulnerability
        resp = Response(
            json.dumps(
                {
                    "string_result": string9,
                    "tainted": is_pyobject_tainted(string9),
                    "ranges": str(get_tainted_ranges(string9)),
                }
            )
        )
        resp.set_cookie("insecure", "cookie", secure=False, httponly=False, samesite="None")

        return resp

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

    @app.route('/source_body/vuln_cmdi', methods=['POST'])
    def cmdi_post():
        command = request.form["cmd"]
        subp = subprocess.Popen(args=[command, "-la", "/"])
        subp.communicate()
        subp.wait()
        return {"result": command, "tainted": is_pyobject_tainted(command),
                "ranges": str(get_tainted_ranges(command))}

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

    @app.route('/weak_randomness', methods=['GET'])
    def weak_randomness():
        result = random.randint(1, 10)
        return {"OK": result}

    @app.route("/insecure_cookie")
    def insecure_cookie():
        resp = Response("OK")
        resp.set_cookie("insecure", "cookie", secure=False, httponly=False, samesite="None")
        return resp

    @app.route("/no_samesite_cookie")
    def nosamesite_insecure_cookie():
        resp = Response("OK")
        resp.set_cookie("insecure", "cookie", secure=True, httponly=True, samesite="None")
        return resp

    @app.route("/no_httponly_cookie")
    def nohttponly_insecure_cookie():
        resp = Response("OK")
        resp.set_cookie("insecure", "cookie", secure=True, httponly=False, samesite="Strict")
        return resp

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
