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

# tee_ids=()
# pub_keys=()

# backupIdxs=("1,2" "0,2" "0,1") # The indexes of the backup servers in the server_configs array

# # Run initial policy simulate for each client config  
# for i in "${!client_configs[@]}"; do  

#     config="${client_configs[$i]}" 

#     node_info_json=$(<"tests/scripts/wallet/node_info.json")
 
#     # Get the backup node infos
#     IFS=',' read -r first second <<< "${backupIdxs[$i]}"  
#     backup_node_infos=$(echo "$node_info_json" | jq --argjson idx1 "$first" --argjson idx2 "$second" '[.[$idx1], .[$idx2]]')

#     # echo "$backup_node_infos"
# done  

node_info_json=$(<"tests/scripts/wallet/node_info.json")
backup_node_infos=$(echo "$node_info_json" | jq --argjson idx1 1 --argjson idx2 2 '[.[$idx1], .[$idx2]]')
node_id=$(echo "$node_info_json" | jq -r --argjson idx1 0 '.[$idx1] | .tee_id')

# backup wallet
instruction_id=$(shuf -i 1-1000000 -n 1)
for j in {0..2}; do   
    go run tests/client/cmd/main.go --call split_wallet --provider $j --walletname foo --instructionid "$instruction_id" --arg1 "$backup_node_infos" --teeid $node_id --rewardepochid 5 --config tests/configs/config_client.toml   
done



