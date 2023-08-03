from locust import HttpUser, task, between


class QuickstartUser(HttpUser):
    wait_time = between(1, 5)

    @task
    def hello_world(self):
        self.client.get("/block", headers={"X-Forwarded-For": "123.45.67.89"})
        self.client.get("/")
        self.client.get("/attack", headers={"X-Forwarded-For": "123.45.67.87", "User-Agent": "dd-test-scanner-log"})
