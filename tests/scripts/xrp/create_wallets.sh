#!/bin/bash  

# Function to cleanup background processes on script exit  
cleanup() {  
    echo "Cleaning up background processes..."  
    kill $(jobs -p) 2>/dev/null  
    exit  
}  

# Set up trap to catch script termination  
trap cleanup EXIT  

# Array of client configs  
declare -a client_configs=(  
    "tests/configs/config_client.toml"  
    "tests/configs/config_client2.toml"  
    "tests/configs/config_client3.toml"  
)  

tee_addresses=() 

node_info_json=$(<"tests/scripts/wallet/node_info.json")

# Run initial policy simulate for each client config

echo "{" > tests/scripts/xrp/addresses.txt
j=0
for config in "${client_configs[@]}"; do  
    # go run tests/client/cmd/main.go --call initial_policy_simulate --config "$config"    

    instruction_id=$(shuf -i 1-1000000 -n 1)
    node_id=$(echo "$node_info_json" | jq -r --argjson idx1 $j '.[$idx1] | .tee_id')

    # Run new wallet commands  
    for i in {0..2}; do   
        go run tests/client/cmd/main.go --call new_wallet --arg1 "$i" --arg2 foo --arg3 $instruction_id --arg4 $node_id --rewardepochid 5 --config "$config"  
    done  

    # # Run pub key command  
    XRP_ADDRESS=$(go run tests/client/cmd/main.go \
        --call wallet_info \
        --arg1 foo \
        --config "$config" \
        | awk -F"XrpAddress: " '{print $2}' | awk -F", " '{print $1}')  

    echo "XRP Address: $XRP_ADDRESS"

    tee_addresses+=("$XRP_ADDRESS")
    echo "tee$j $XRP_ADDRESS" >> tests/scripts/xrp/addresses.txt


    j=$(($j+1))
done  
# printf "{" > tests/scripts/xrp/addresses.txt  
# printf "%s\n" "${tee_addresses[@]}" > tests/scripts/xrp/addresses.txt  

echo "}" >> tests/scripts/xrp/addresses.txt
