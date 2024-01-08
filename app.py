import logging

from project.app import create_app

logging.basicConfig(level=logging.DEBUG)

app = create_app()

if __name__ == '__main__':
    app.config["SESSION_COOKIE_SECURE"] = False
    app.run(debug=True, port=8000)
