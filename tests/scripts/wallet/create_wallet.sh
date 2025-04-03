#!/bin/bash  

# Function to cleanup background processes on script exit  
cleanup() {  
    echo "Cleaning up background processes..."  
    kill $(jobs -p) 2>/dev/null  
    exit  
}  

# Set up trap to catch script termination  
trap cleanup EXIT  

case "$1" in  
  --remote)  
    config_file="tests/configs/config_remote.toml"
    ;;
  --local)  
    config_file="tests/configs/config_client.toml"
    ;;
  *)  
    echo "ERROR: Unknown option: $1"  
    echo "Usage: $0 --remote | --local"  
    exit 1  
    ;;  
esac  

node_info_json=$(<"tests/scripts/generated/node_info.json")
node_id=$(echo "$node_info_json" | jq -r --argjson idx1 0 '.[$idx1] | .tee_id')

active_policy_json=$(<"tests/scripts/generated/active_policy.json")
epoch_id=$(echo "$active_policy_json" | jq -r '.epochId')

# Create a new wallet
instruction_id=$(shuf -i 1-1000000 -n 1)
for i in {0..2}; do   
    go run tests/client/cmd/main.go --call new_wallet --provider $i --walletid "0x6969" --keyid "6969" \
    --instructionid $instruction_id --teeid $node_id --rewardepochid $epoch_id --config $config_file
done  