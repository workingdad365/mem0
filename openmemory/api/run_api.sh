
# Activate virtual environment
source .venv/bin/activate

# Disable telemetry
export MEM0_TELEMETRY=False

# Run the API server
uvicorn main:app --host 0.0.0.0 --port 8765 --log-level debug
