#!/bin/bash
# Runs inside the container environment.

# Ensure output directories exist
mkdir -p /logs/verifier

# Start mock OSV service in background
python /app/mock_osv.py > /logs/verifier/mock_osv.log 2>&1 &
MOCK_OSV_PID=$!

# Start Flask verification service in background
python /app/app.py > /logs/verifier/app.log 2>&1 &
APP_PID=$!

# Run the pytest suite
pytest --ctrf /logs/verifier/ctrf.json D:/Snorkel/S1D:/Snorkel/S1D:/Snorkel/S1D:/Snorkel/S1/tests/test_outputs.py -rA
TEST_EXIT_CODE=$?

# Clean up background services
kill $MOCK_OSV_PID
kill $APP_PID

# Write final reward file
if [ $TEST_EXIT_CODE -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi

exit $TEST_EXIT_CODE
