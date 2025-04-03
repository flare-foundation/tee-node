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
    declare -a client_configs=(  
        "tests/configs/config_remote.toml"
        "tests/configs/config_remote2.toml"
        "tests/configs/config_remote3.toml"
    )  
    ;;
  --local)  
    declare -a client_configs=(  
        "tests/configs/config_client.toml"  
        "tests/configs/config_client2.toml"  
        "tests/configs/config_client3.toml"  
    )  
    ;;
  *)  
    echo "ERROR: Unknown option: $1"  
    echo "Usage: $0 --remote | --local"  
    exit 1  
    ;;  
esac  

tee_addresses=() 


node_info_json=$(<"tests/scripts/generated/node_info.json")

active_policy_json=$(<"tests/scripts/generated/active_policy.json")
epoch_id=$(echo "$active_policy_json" | jq -r '.epochId')

echo "{" > tests/scripts/generated/xrp/addresses.txt
for conf_idx in "${!client_configs[@]}"; do 

    node_id=$(echo "$node_info_json" | jq -r --argjson idx1 $conf_idx '.[$idx1] | .tee_id')

    instruction_id=$(shuf -i 1-1000000 -n 1)

    # Run new wallet commands  
    for provider_idx in {0..2}; do   
        go run tests/client/cmd/main.go --call new_wallet --provider $provider_idx --walletid "0x4321" --keyid "4321${conf_idx}" \
        --instructionid $instruction_id --teeid $node_id --rewardepochid $epoch_id --config "${client_configs[$conf_idx]}"
    done  

    # # Run pub key command  
    command_output=$(go run tests/client/cmd/main.go \
        --call wallet_info \
        --walletid "0x4321" --keyid "4321${conf_idx}" \
        --config "${client_configs[$conf_idx]}" )
    echo "$command_output"
    XRP_ADDRESS=$(echo "$command_output" | awk -F"XrpAddress: " '{print $2}' | awk -F", " '{print $1}')  

    echo "XRP Address: $XRP_ADDRESS"

    tee_addresses+=("$XRP_ADDRESS")
    echo "tee$conf_idx $XRP_ADDRESS" >> tests/scripts/generated/xrp/addresses.txt
done  
# printf "{" > tests/scripts/generated/xrp/addresses.txt  
# printf "%s\n" "${tee_addresses[@]}" > tests/scripts/generated/xrp/addresses.txt  

echo "}" >> tests/scripts/generated/xrp/addresses.txt
