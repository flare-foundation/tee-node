#!/bin/bash  

# Function to cleanup background processes on script exit  
cleanup() {  
    echo "Cleaning up background processes..."  
    kill $(jobs -p) 2>/dev/null  
    exit  
}  

# Set up trap to catch script termination  
trap cleanup EXIT  

# Array of server configs  
declare -a server_configs=(  
    "tests/configs/config_server.toml"  
    "tests/configs/config_server_backup0.toml"  
    "tests/configs/config_server_backup1.toml"  
)  

# Start servers  
echo "Starting servers..."  
for config in "${server_configs[@]}"; do  
    echo "Starting server with config: $config"  
    go run cmd/server/main.go --config "$config" > "tests/scripts/logs/server_$(basename "$config").log" 2>&1 &  
    # Store PID  
    server_pids+=($!)  
    # Wait a bit between server starts  
    # sleep 2  
done  


echo "Press Ctrl+C to stop all servers and exit."  

# Keep script running until manually terminated  
wait ${server_pids[@]}