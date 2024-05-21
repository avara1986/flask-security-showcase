import json
import logging
import os
import random
import resource
import sqlite3
import subprocess

import requests
from ddtrace.internal.service import ServiceStatus
from ddtrace.internal.telemetry import telemetry_writer
from flask import Flask, Response, request

logging.basicConfig(level=logging.DEBUG)
LOGS_FILE = os.path.dirname(__file__)
from Crypto.Cipher import AES


def unsafe_sql_format(query_string, *args, **kwargs):
    # Note that this function should only be used for formatting metadata
    # in a query string. Metadata includes table names, column names and
    # order type.
    return query_string.format(*args, **kwargs)


def create_app():
    from ddtrace.appsec._iast._taint_tracking import (get_tainted_ranges,
                                                      is_pyobject_tainted)

    app = Flask(__name__)

    @app.route("/")
    def helthcheck():
        return "OK"

    @app.route('/iast/propagation', methods=['POST'])
    @app.route("/iast/propagation", methods=["GET"])
    def iast_propagation():
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
        string4 = "-".join(
            [string3, string3, string3]
        )  # 6 propagation ranges: hiroot1234-hiroot1234-hiroot1234
        string5 = string4[0:20]  # 1 propagation range: hiroot1234-hiroot123
        string6 = string5.title()  # 1 propagation range: Hiroot1234-Hiroot123
        string7 = string6.upper()  # 1 propagation range: HIROOT1234-HIROOT123
        string8 = (
            "%s_notainted" % string7
        )  # 1 propagation range: HIROOT1234-HIROOT123_notainted
        string9 = "notainted_{}".format(
            string8
        )  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted
        string10 = (
            "nottainted\n" + string9
        )  # 2 propagation ranges: notainted\nnotainted_HIROOT1234-HIROOT123_notainted
        string11 = string10.splitlines()[
            1
        ]  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted
        string12 = (
            string11 + "_notainted"
        )  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted_notainted
        string13 = string12.rsplit("_", 1)[
            0
        ]  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted

        try:
            # Path traversal vulnerability
            m = open("/" + string13 + ".txt")
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
            requests.get("http://" + "foobar")
            # urllib3.request("GET", "http://" + "foobar")
        except Exception:
            pass

        # Weak Randomness vulnerability
        _ = random.randint(1, 10)

        # os path propagation
        string14 = os.path.join(
            string13, "a"
        )  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted/a
        string15 = os.path.split(string14)[
            0
        ]  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted
        string16 = os.path.dirname(
            string15 + "/" + "foobar"
        )  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted
        string17 = os.path.basename(
            "/foobar/" + string16
        )  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted
        string18 = os.path.splitext(string17 + ".jpg")[
            0
        ]  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted
        string19 = os.path.normcase(
            string18
        )  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted
        string20 = os.path.splitdrive(string19)[
            1
        ]  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted

        expected = "notainted_HIROOT1234-HIROOT123_notainted"  # noqa: F841
        assert (
            string20 == expected
        ), f"Error, string20 is\n{string20}\nExpected:\n{expected}"

        # Insecure Cookie vulnerability
        resp = Response(
            json.dumps(
                {
                    "memory": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
                    "string_result": string20,
                    "tainted": is_pyobject_tainted(string20),
                    "ranges": str(get_tainted_ranges(string20)),
                }
            )
        )
        resp.set_cookie(
            "insecure", "cookie", secure=False, httponly=False, samesite="None"
        )
        resp.headers["Vary"] = tainted_string_2
        resp.headers["Header-Injection"] = tainted_string_2

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
        string4 = "-".join(
            [string3, string3, string3]
        )  # 6 propagation ranges: hiroot1234-hiroot1234-hiroot1234
        string5 = string4[0:20]  # 1 propagation range: hiroot1234-hiroot123
        string6 = string5.title()  # 1 propagation range: Hiroot1234-Hiroot123
        string7 = string6.upper()  # 1 propagation range: HIROOT1234-HIROOT123
        string8 = (
            "%s_notainted" % string7
        )  # 1 propagation range: HIROOT1234-HIROOT123_notainted
        string9 = "notainted_{}".format(
            string8
        )  # 1 propagation range: notainted_HIROOT1234-HIROOT123_notainted

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
        resp.set_cookie(
            "insecure", "cookie", secure=False, httponly=False, samesite="None"
        )

        return resp

    @app.route("/source_header/vuln_path_traversal")
    def path_traversal_header():
        file_path = request.headers.get("pt-file", "")
        result = "NO_FILE"

        if file_path:
            # result = pt_open2(file_path)
            m = open(file_path)
            result = m.read()
        return {
            "result": result,
            "tainted": is_pyobject_tainted(file_path),
            "ranges": str(get_tainted_ranges(file_path)),
        }

    @app.route("/source_queryparam/vuln_path_traversal", methods=["GET"])
    def path_traversal_get():
        file_path = request.args.get("pt_file")
        result = "NO_FILE"
        if file_path:
            # result = pt_open2(file_path)
            m = open(file_path)
            result = m.read()
        return {
            "result": result,
            "tainted": is_pyobject_tainted(file_path),
            "ranges": str(get_tainted_ranges(file_path)),
        }

    @app.route("/source_queryparam/vuln_sqli", methods=["GET"])
    def sqli_get():
        table = request.args.get("table")
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute("CREATE TABLE students (name TEXT, addr TEXT, city TEXT, pin TEXT)")
        cur.execute("SELECT 1 FROM " + table)
        rows = cur.fetchall()
        return {
            "result": rows,
            "tainted1": is_pyobject_tainted(table),
            "tainted2": is_pyobject_tainted("SELECT 1 FROM " + table),
            "ranges": str(get_tainted_ranges(table)),
        }

    @app.route("/source_body/vuln_sqli", methods=["POST"])
    def sqli_post():
        password_u = request.form.get("password")
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute(
            "CREATE TABLE students (id TEXT, password TEXT, city TEXT, pin TEXT)"
        )
        cur.execute("SELECT 1 FROM students WHERE password = '" + password_u + "'")
        rows = cur.fetchall()
        return {
            "result": rows,
            "tainted": is_pyobject_tainted(password_u),
            "ranges": str(get_tainted_ranges(password_u)),
        }

    @app.route("/source_body/vuln_cmdi", methods=["POST"])
    def cmdi_post():
        command = request.form["cmd"]
        subp = subprocess.Popen(args=[command, "-la", "/"])
        subp.communicate()
        subp.wait()
        return {
            "result": command,
            "tainted": is_pyobject_tainted(command),
            "ranges": str(get_tainted_ranges(command)),
        }

    @app.route("/source_header/vuln_sqli")
    def sqli_header():
        password_u = request.headers.get("password", "")
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute(
            "CREATE TABLE students (id TEXT, password TEXT, city TEXT, pin TEXT)"
        )
        cur.execute("SELECT 1 FROM students WHERE password = '" + password_u + "'")
        rows = cur.fetchall()
        return {
            "result": rows,
            "tainted": is_pyobject_tainted(password_u),
            "ranges": str(get_tainted_ranges(password_u)),
        }

    @app.route("/source_pathparam/vuln_sqli/<password>")
    def sqli_pathparam(password):
        con = sqlite3.connect(":memory:")
        cur = con.cursor()

        cur.execute(
            "CREATE TABLE students (id TEXT, password TEXT, city TEXT, pin TEXT)"
        )
        cur.execute("SELECT 1 FROM students WHERE password = '" + password + "'")
        rows = cur.fetchall()
        return {
            "result": rows,
            "tainted": is_pyobject_tainted(password),
            "ranges": str(get_tainted_ranges(password)),
        }

    @app.route("/source_pathparam/vuln_cmdi/<filename>")
    def cmdi_pathparam(filename):
        subp = subprocess.Popen(args=["ls", "-la", filename])
        subp.communicate()
        subp.wait()
        return {
            "result": filename,
            "tainted": is_pyobject_tainted(filename),
            "ranges": str(get_tainted_ranges(filename)),
        }

    @app.route("/source_queryparam/vuln_cmdi", methods=["GET"])
    def cmdi_get():
        filename = request.args.get("filename")
        subp = subprocess.Popen(args=["ls", "-la", filename])
        subp.communicate()
        subp.wait()
        return {
            "result": filename,
            "tainted": is_pyobject_tainted(filename),
            "ranges": str(get_tainted_ranges(filename)),
        }

    @app.route("/weak_randomness", methods=["GET"])
    def weak_randomness():
        key = b"Sixteen byte key"
        data = b"abcdefgh"
        crypt_obj = AES.new(key, AES.MODE_EAX)
        result = crypt_obj.encrypt(data)
        return {"OK": str(result)}

    @app.route("/weak_hash", methods=["GET"])
    def weak_hash():
        import hashlib

        m = hashlib.md5()
        m.update(b"Nobody inspects")
        m.update(b" the spammish repetition")
        # label parametrized_weak_hash
        result = m.hexdigest()
        return {"OK": str(result)}

    @app.route("/insecure_cookie")
    def insecure_cookie():
        resp = Response("OK")
        resp.set_cookie(
            "insecure", "cookie", secure=False, httponly=False, samesite="None"
        )
        return resp

    @app.route("/no_samesite_cookie")
    def nosamesite_insecure_cookie():
        resp = Response("OK")
        resp.set_cookie(
            "insecure", "cookie", secure=True, httponly=True, samesite="None"
        )
        return resp

    @app.route("/no_httponly_cookie")
    def nohttponly_insecure_cookie():
        resp = Response("OK")
        resp.set_cookie(
            "insecure", "cookie", secure=True, httponly=False, samesite="Strict"
        )
        return resp

    @app.route("/metrics")
    def metrics_view():
        # telemetry_metrics_writer.add_count_metric(
        #         TELEMETRY_NAMESPACE_TAG_TRACER,
        #         "test_metric",
        #         1.0,
        #     )
        namespace_metrics = telemetry_writer._namespace.get()
        metrics = [
            m.to_dict()
            for payload_type, namespaces in namespace_metrics.items()
            for namespace, metrics in namespaces.items()
            for m in metrics.values()
        ]
        return {
            "telemetry_metrics_writer_running": telemetry_writer.status
            == ServiceStatus.RUNNING,
            "telemetry_metrics_writer_worker": telemetry_writer._worker is not None,
            "telemetry_metrics_writer_queue": metrics,
        }, 200

    @app.route("/normal")
    def normal():
        return "OK"

    @app.route("/attack")
    def attack():
        return "OK"

    @app.route("/block")
    def block():
        return "OK"

    return app
