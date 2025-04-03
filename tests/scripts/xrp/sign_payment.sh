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

# Array of addresses
declare -a addresses 
addresses=$(<"tests/scripts/generated/xrp/addresses.txt")
node_info_json=$(<"tests/scripts/generated/node_info.json")

readonly MULTISIG_ACCOUNT="rGumsQrNYzwW4xDPMmC3qXCJ5XqqsDBkat"  

declare -a payment_hashes=()  
declare -a instruction_ids=()
declare -a accounts=()  
declare -a signatures=()  
declare -a public_keys=()  

active_policy_json=$(<"tests/scripts/generated/active_policy.json")
epoch_id=$(echo "$active_policy_json" | jq -r '.epochId')

# Run initial policy simulate for each client config  
for conf_idx in "${!client_configs[@]}"; do 

    address=$(echo "$addresses" | grep -o "tee$conf_idx [a-zA-Z0-9]*" | cut -d' ' -f2)
    echo $address

    # Create JSON payload
    payment_json='{  
        "amount": 9950000,  
        "fee": 990,  
        "spenderAccount": "'"$MULTISIG_ACCOUNT"'",
        "destinationAccount": "'"$address"'",  
        "sequence": 4979782,  
        "lastLedgerSeq": 5050107,  
        "signerAddress": "'"$address"'"  
    }' 
    # echo $payment_json

    # Execute command with JSON payload  
    PAYMENT_HASH=$(go run tests/client/cmd/main.go \
        --call hash_payment \
        --arg1="$payment_json" \
        --config "${client_configs[$conf_idx]}" \
        | grep "Payment hash:" \
        | awk '{print $NF}')  
    payment_hashes+=("$PAYMENT_HASH")
    echo $PAYMENT_HASH

    instruction_id=$(shuf -i 1-1000000 -n 1)
    instruction_ids+=("$instruction_id")

    node_id=$(echo "$node_info_json" | jq -r --argjson idx1 $conf_idx '.[$idx1] | .tee_id')
    
    for signer_idx in {0..2}; do  
        res=$(go run tests/client/cmd/main.go --call sign_payment --provider $signer_idx \
        --walletid "0x4321" --keyid "4321${conf_idx}" --instructionid $instruction_id \
        --teeid $node_id --arg1 $PAYMENT_HASH --rewardepochid $epoch_id --config "${client_configs[$conf_idx]}")
    done  


    # Capture the account info
    command_output=$(go run tests/client/cmd/main.go --call get_payment_signature \
        --instructionid $instruction_id \
        --config "${client_configs[$conf_idx]}")  

    # Extract Account Info
    account=$(echo "$command_output" | grep -o "Account [^,]*" | cut -d' ' -f2)  
    txn_signature=$(echo "$command_output" | grep -o "TxnSignature [^,]*" | cut -d' ' -f2) 
    public_key=$(echo "$command_output" | grep -o "PublicKey [^,]*" | cut -d' ' -f2)  

    accounts+=("$account")
    signatures+=("$txn_signature")
    public_keys+=("$public_key")
done  


# Write to file with clear formatting  
{  
    echo "=== Payment Information ==="  
    for i in "${!payment_hashes[@]}"; do  
        echo -e "\nEntry $((i+1)):"  
        echo "Payment Hash: ${payment_hashes[$i]}"  
        echo "Instruction ID: ${instruction_ids[$i]}"
        echo "Account: ${accounts[$i]}"  
        echo "TxnSignature: ${signatures[$i]}"  
        echo "PublicKey: ${public_keys[$i]}"  
        echo "----------------------------------------"  
    done  
} > tests/scripts/generated/xrp/signatures.txt  

# Write to file with JSON formatting  
{   
    echo "["
    for i in "${!payment_hashes[@]}"; do  
        echo "{"  
        echo "    \"payment_hash\": \"${payment_hashes[$i]}\","  
        echo "    \"instruction_id\": \"${instruction_ids[$i]}\","
        echo "    \"account\": \"${accounts[$i]}\","  
        echo "    \"signature\": \"${signatures[$i]}\","  
        echo "    \"public_key\": \"${public_keys[$i]}\""  
        echo "}"  
        [[ $i -lt $((${#payment_hashes[@]}-1)) ]] && echo ","  
    done  
    echo "]"
} > tests/scripts/generated/xrp/signatures.json  