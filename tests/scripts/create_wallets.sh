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

# Run initial policy simulate for each client config  
for config in "${client_configs[@]}"; do  
    go run tests/client/cmd/main.go --call initial_policy_simulate --config "$config"  
    sleep 1  

    # Run new wallet commands  
    for i in {0..1}; do   
        go run tests/client/cmd/main.go --call new_wallet --arg1 "$i" --arg2 foo --config "$config"  
        sleep 1  
    done  

    # # Run pub key command  
    XRP_ADDRESS=$(go run tests/client/cmd/main.go \
        --call multisig_account_info \
        --arg1 foo \
        --config "$config" \
        | awk -F"xrpAddress: " '{print $2}' | awk -F", " '{print $1}')  

    echo "XRP Address: $XRP_ADDRESS"

    tee_addresses+=("$XRP_ADDRESS")  
done  

printf "%s\n" "${tee_addresses[@]}" > tests/scripts/addresses.txt  
