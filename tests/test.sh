#!/bin/bash
# Runs inside the container environment.

# Ensure verifier log directory exists
mkdir -p /logs/verifier

# Start local mock OSV service
python /app/mock_osv.py > /logs/verifier/mock_osv.log 2>&1 &
MOCK_OSV_PID=$!

# Start main verification API service
python /app/app.py > /logs/verifier/app.log 2>&1 &
APP_PID=$!

# Register exit trap to clean up services on exit
trap 'kill $MOCK_OSV_PID $APP_PID 2>/dev/null' EXIT

# Give services a moment to start
sleep 2

# Run the test suite
pytest --ctrf /logs/verifier/ctrf.json D:/Snorkel/S1D:/Snorkel/S1D:/Snorkel/S1D:/Snorkel/S1D:/Snorkel/S1D:/Snorkel/S1/tests/test_outputs.py -rA
if [ $? -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
