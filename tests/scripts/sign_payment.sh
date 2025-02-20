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
# Array of addresses
declare -a addresses  
mapfile -t addresses < tests/scripts/addresses.txt

readonly MULTISIG_ACCOUNT="rGumsQrNYzwW4xDPMmC3qXCJ5XqqsDBkat"  

declare -a payment_hashes=()  
declare -a accounts=()  
declare -a signatures=()  
declare -a public_keys=()  

# Run initial policy simulate for each client config  
for i in "${!client_configs[@]}"; do  
    # Create JSON payload  
    payment_json='{  
        "amount": 9950000,  
        "fee": 990,  
        "spenderAccount": "'"$MULTISIG_ACCOUNT"'",
        "destinationAccount": "'"${addresses[0]}"'",  
        "sequence": 4979782,  
        "lastLedgerSeq": 5050107,  
        "signerAddress": "'"${addresses[$i]}"'"  
    }' 

    # Execute command with JSON payload  
    PAYMENT_HASH=$(go run tests/client/cmd/main.go \
        --call hash_payment \
        --arg1="$payment_json" \
        --config "${client_configs[$i]}" \
        | grep "Payment hash:" \
        | awk '{print $NF}')  

    payment_hashes+=("$PAYMENT_HASH")

    for signer_idx in {0..1}; do  
        res=$(go run tests/client/cmd/main.go --call sign_payment --arg1 "$signer_idx" --arg2="foo" --arg3 $PAYMENT_HASH --config "${client_configs[$i]}")
    done  

    # Capture the account info
    command_output=$(go run tests/client/cmd/main.go --call get_payment_signature --arg1="foo" --arg2 $PAYMENT_HASH --config "${client_configs[$i]}")  

    

    # Extract Account Info
    account=$(echo "$command_output" | grep -o "Account [^,]*" | cut -d' ' -f2)  
    txn_signature=$(echo "$command_output" | grep -o "TxnSignature [^,]*" | cut -d' ' -f2) 
    public_key=$(echo "$command_output" | grep -o "PublicKey [^,]*" | cut -d' ' -f2)  


    priv_key=$(echo "$command_output" | grep -o "PrivKey: [^,]*" | cut -d' ' -f2)  
    echo "Private Key: $priv_key"


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
        echo "Account: ${accounts[$i]}"  
        echo "TxnSignature: ${signatures[$i]}"  
        echo "PublicKey: ${public_keys[$i]}"  
        echo "----------------------------------------"  
    done  
} > tests/scripts/signatures.txt  

# Write to file with JSON formatting  
{   
    echo "["
    for i in "${!payment_hashes[@]}"; do  
        echo "{"  
        echo "    \"payment_hash\": \"${payment_hashes[$i]}\","  
        echo "    \"account\": \"${accounts[$i]}\","  
        echo "    \"signature\": \"${signatures[$i]}\","  
        echo "    \"public_key\": \"${public_keys[$i]}\""  
        echo "}"  
        [[ $i -lt $((${#payment_hashes[@]}-1)) ]] && echo ","  
    done  
    echo "]"
} > tests/scripts/signatures.json  