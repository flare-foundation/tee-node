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
backup_node_infos=$(echo "$node_info_json" | jq --argjson idx1 1 --argjson idx2 2 '[.[$idx1], .[$idx2]]')
node_id=$(echo "$node_info_json" | jq -r --argjson idx1 0 '.[$idx1] | .tee_id')

active_policy_json=$(<"tests/scripts/generated/active_policy.json")
epoch_id=$(echo "$active_policy_json" | jq -r '.epochId')

wallet_info=$(go run tests/client/cmd/main.go \
    --call wallet_info \
    --walletid "0x6969" --keyid "6969" \
    --config "$config_file" )

public_key=$(echo "$wallet_info" | grep -o "PublicKey: [^,]*" | cut -d' ' -f2)  


# download backup
go run tests/client/cmd/main.go --call save_wallet_backup --walletid "0x6969" --keyid "6969" \
 --teeid $node_id --rewardepochid $epoch_id --pubkey "$public_key" --config $config_file


# delete, restore todo