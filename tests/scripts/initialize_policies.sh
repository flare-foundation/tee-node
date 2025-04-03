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

tee_ids=()
pub_keys=()

# Run initial policy simulate for each client config  
for config in "${client_configs[@]}"; do  
    command_output=$(go run tests/client/cmd/main.go \
        --call initial_policy_simulate \
        --config "$config") 

    active_epoch=$(echo "$command_output" | grep -o "Active EpochID: [0-9]*" | cut -d' ' -f3) 
    echo "Active EpochID: $active_epoch"

    command_output=$(go run tests/client/cmd/main.go \
        --call node_attestation \
        --config "$config")  

    tee_id=$(echo "$command_output" | grep -o "TeeId: [^,]*" | cut -d' ' -f2)  
    pub_key=$(echo "$command_output" | grep -o "PubKey: [^,]*" | cut -d' ' -f2)  

    echo "TeeId: $tee_id"
    echo "PubKey: $pub_key"

    tee_ids+=("$tee_id")
    pub_keys+=("$pub_key")
    
done  

# Write to file with clear formatting  
{  
    echo "=== Node Information ==="  
    echo "Active EpochID: $active_epoch"
    for i in "${!tee_ids[@]}"; do  
        echo -e "\nEntry $((i+1)):"  
        echo "TeeId: ${tee_ids[$i]}"
        echo "PubKey: ${pub_keys[$i]}"
        echo "----------------------------------------"  
    done  
} > tests/scripts/generated/node_info.txt  

# Write to file with JSON formatting  
{   
    echo "["
    for i in "${!tee_ids[@]}"; do  
        echo "{"  
        echo "    \"tee_id\": \"${tee_ids[$i]}\","  
        echo "    \"pub_key\": \"${pub_keys[$i]}\""
        echo "}"  
        [[ $i -lt $((${#tee_ids[@]}-1)) ]] && echo ","  
    done  
    echo "]"
} > tests/scripts/generated/node_info.json  

{
    echo "{"
    echo "    \"epochId\": \"$active_epoch\""
    echo "}"
} > tests/scripts/generated/active_policy.json


