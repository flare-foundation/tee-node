#!/bin/bash  

# Function to cleanup background processes on script exit  
cleanup() {  
    echo "Cleaning up background processes..."  
    kill $(jobs -p) 2>/dev/null  
    exit  
}  

# Set up trap to catch script termination  
trap cleanup EXIT  


node_info_json=$(<"tests/scripts/wallet/node_info.json")
node_id=$(echo "$node_info_json" | jq -r --argjson idx1 0 '.[$idx1] | .tee_id')

# Create a new wallet
instruction_id=$(shuf -i 1-1000000 -n 1)
for i in {0..2}; do   
    go run tests/client/cmd/main.go --call new_wallet --provider $i --walletname foo --instructionid $instruction_id --teeid $node_id --rewardepochid 5 --config tests/configs/config_client.toml
done  