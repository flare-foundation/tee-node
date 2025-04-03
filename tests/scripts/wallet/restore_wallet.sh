#!/bin/bash  

# Function to cleanup background processes on script exit  
cleanup() {  
    echo "Cleaning up background processes..."  
    kill $(jobs -p) 2>/dev/null  
    exit  
}  

# Process command-line arguments  
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

# Set up trap to catch script termination  
trap cleanup EXIT  

command_output=$(go run tests/client/cmd/main.go --call wallet_info --walletid "0x6969" --keyid "6969" --config $config_file)
address=$(echo "$command_output" | grep -o "EthAddress: [^,]*" | cut -d' ' -f2)
echo "Address: $address"

node_info_json=$(<"tests/scripts/generated/node_info.json")
node_id=$(echo "$node_info_json" | jq -r --argjson idx1 0 '.[$idx1] | .tee_id')
node_pub_key=$(echo "$node_info_json" | jq -r --argjson idx1 0 '.[$idx1] | .pub_key')

tee_ids=$(echo "$node_info_json" | jq -r --argjson idx1 1 --argjson idx2 2 '.[$idx1].tee_id, .[$idx2].tee_id')

active_policy_json=$(<"tests/scripts/generated/active_policy.json")
epoch_id=$(echo "$active_policy_json" | jq -r '.epochId')

# # Restore a wallet
instruction_id=$(shuf -i 1-1000000 -n 1)
for i in {0..2}; do 
    go run tests/client/cmd/main.go --call recover_wallet --provider $i --walletid "0x6969" --keyid "6969" --backupid "6969" \
    --instructionid $instruction_id --teeid $node_id --pubkey $node_pub_key --teeids $tee_ids \
    --address $address --rewardepochid "$epoch_id" --config $config_file
done




