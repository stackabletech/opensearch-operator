import logging
import os
import requests
import sys

logging.basicConfig(
    level="DEBUG", format="%(asctime)s %(levelname)s: %(message)s", stream=sys.stdout
)

namespace = os.environ["NAMESPACE"]
opensearch_user = os.environ["OPENSEARCH_USER"]
opensearch_password = os.environ["OPENSEARCH_PASSWORD"]
opensearch_dashboards_service = "http://opensearch-dashboards:5601"

session = requests.Session()
session.headers.update({"osd-xsrf": "true"})

login_page = session.post(
    f"{opensearch_dashboards_service}/auth/login",
    data={"username": opensearch_user, "password": opensearch_password},
)
assert login_page.ok, "Failed to login to OpenSearch Dashboards"

api_status = session.get(f"{opensearch_dashboards_service}/api/status")
assert api_status.ok, "Failed to get API status"

opensearch_version = api_status.json()["version"]["number"]

assert api_status.json()["status"]["overall"]["state"] == "green", (
    "Overall state of OpenSearch Dashboards is not green"
)

# Check if all expected plugins are present and working
expected_plugins = [
    "alertingDashboards",
    "anomalyDetectionDashboards",
    "assistantDashboards",
    "customImportMapDashboards",
    "flowFrameworkDashboards",
    "indexManagementDashboards",
    "mlCommonsDashboards",
    "notificationsDashboards",
    "observabilityDashboards",
    "queryInsightsDashboards",
    "queryWorkbenchDashboards",
    "reportsDashboards",
    "searchRelevanceDashboards",
    "securityAnalyticsDashboards",
    "securityDashboards",
]

states = {}
for status in api_status.json()["status"]["statuses"]:
    states[
        status["id"].removeprefix("plugin:").removesuffix(f"@{opensearch_version}")
    ] = status["state"] == "green"
for plugin in expected_plugins:
    assert plugin in states and states[plugin], (
        f"Expected plugin {plugin} not present or working."
    )

# Load Sample Data (web logs & flights)
sample_web_logs = session.post(f"{opensearch_dashboards_service}/api/sample_data/logs")
assert sample_web_logs.ok, "Failed to create sample data (logs)"

sample_flights = session.post(
    f"{opensearch_dashboards_service}/api/sample_data/flights"
)
assert sample_flights.ok, "Failed to create sample data (flights)"

# Check that the indices were created
indices = session.get(
    f"{opensearch_dashboards_service}/api/saved_objects/_find?fields=title&per_page=10000&type=index-pattern"
)
assert indices.ok, "Failed to get indices"

logs_index = indices.json()["saved_objects"][0]
assert logs_index["attributes"]["title"] == "opensearch_dashboards_sample_data_logs", (
    "First index should be sample logs"
)

flights_index = indices.json()["saved_objects"][1]
assert (
    flights_index["attributes"]["title"] == "opensearch_dashboards_sample_data_flights"
), "Second index should be sample flights"
