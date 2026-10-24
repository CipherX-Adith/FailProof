import json
import sqlite3
c = sqlite3.connect('../frontend/.codex-tmp/phase3-live.sqlite3')
for row in c.execute("select state, actual_status, error_detail, endpoint_path, method from api_test_results where run_id='3d01dbb3-c929-44a7-a862-4d46dc379c3e'"):
    print(json.dumps(row))
