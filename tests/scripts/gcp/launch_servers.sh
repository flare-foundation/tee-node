#!/bin/bash  

# Function to display usage/help message  
show_usage() {  
  echo "Usage: $0 [OPTION]"  
  echo "Execute specific sections of the script based on the provided flag."  
  echo ""  
  echo "Options:"  
  echo "  --build-docker    Build and push the docker image"  
  echo "  --launch-instances    Launch the instances"  
  echo "  --stop-instances    Stop the instances"  
  echo ""  
  echo "You must specify exactly one flag."  
  exit 1  
}  


build_and_push_docker_image() {  
    echo "Building and pushing docker image, this may take a minute..."

    docker build -t us-docker.pkg.dev/flare-network-sandbox/flare-tee/tee-node:latest --no-cache .

    gcloud auth configure-docker us-docker.pkg.dev

    docker push us-docker.pkg.dev/flare-network-sandbox/flare-tee/tee-node:latest
}  


launch_instances() {
    echo "Launching instances, this may take a minute..."

    # Extract NAME, STATUS, EXTERNAL_IP for a given instance name
    extract_instance_info() {  
      local instance_name="$1"  
      
      local instance_data=$(gcloud compute instances list | grep "^$instance_name[[:space:]]" | awk '{print $1","$NF","$5}')  
      
      if [ -n "$instance_data" ]; then  
          echo "$instance_data"  
      else  
          echo "$instance_name,NOT_FOUND,N/A"  
      fi  
    }  

    instances=("script-test-tee-node-1" "script-test-tee-node-2" "script-test-tee-node-3")

    instance_info=()
    for instance_name in "${instances[@]}"; do  
    instance_info+=("$(extract_instance_info "$instance_name")")
    done  

    external_ips=()

    # If Instance is not running, Launch it!
    for i in "${!instance_info[@]}"; do
        instance_name=$(echo "${instance_info[$i]}" | cut -d ',' -f 1)

        if [[ ${instance_info[$i]} != *"RUNNING"* ]]; then
            command_output=$(gcloud compute instances create "$instance_name" \
            --confidential-compute-type=SEV \
            --shielded-secure-boot \
            --scopes=cloud-platform \
            --zone=us-central1-a \
            --maintenance-policy=TERMINATE \
            --image-project=confidential-space-images \
            --image-family=confidential-space-debug \
            --service-account=confidential-sa@flare-network-sandbox.iam.gserviceaccount.com \
            --tags=rpc-server,tee-ws \
            --metadata="^~^tee-image-reference=us-docker.pkg.dev/flare-network-sandbox/flare-tee/tee-node:latest")

            echo "$command_output"

            external_ip=$(echo "$command_output" | grep $instance_name | awk '{print $5}')  
            instance_info[$i]="$instance_name,RUNNING,$external_ip"
            external_ips+=("$external_ip")
        else
            external_ip=$(echo "${instance_info[$i]}" | cut -d ',' -f 3)
            external_ips+=("$external_ip")
            echo "Instance $instance_name is already running"        
        fi
    done

    # Output file  
    output_file="tests/scripts/generated/gcp/instance_info.txt"
    remote_client_conf_file1="tests/configs/config_remote.toml"  
    remote_client_conf_file2="tests/configs/config_remote2.toml"  
    remote_client_conf_file3="tests/configs/config_remote3.toml"   

    # Create sed commands for each line  
    sed_command=""  
    for k in "${!external_ips[@]}"; do
      line_num=$((k+11))  # Start at line 11  
      if [[ $line_num -le 13 ]]; then  # Only modify up to line 13
        index=$((k+1))  
        replacement="SERVER_IP_$index = \"${external_ips[$k]}\""  
        # Escape special characters for sed  
        replacement=$(echo "$replacement" | sed 's/[\/&]/\\&/g')  
        sed_command+="${line_num}s/.*/$replacement/;"  
      fi  
    done  

    # Apply the changes  
    sed -i "$sed_command" "$output_file"  
    sed -i "$sed_command" "$remote_client_conf_file1"  
    sed -i "$sed_command" "$remote_client_conf_file2"  
    sed -i "$sed_command" "$remote_client_conf_file3"  

    echo "Instances launched successfully"
    echo "IP addresses written to lines 11-13 in the config files"  
}


stop_instances() {
    echo "Stopping instances, this may take a minute..."

    instances=("script-test-tee-node-1" "script-test-tee-node-2" "script-test-tee-node-3")

    for instance_name in "${instances[@]}"; do  
        gcloud compute instances delete $instance_name --zone=us-central1-a --quiet
    done  
}




# Process command-line arguments  
case "$1" in  
  --build-docker)  
    build_and_push_docker_image
    ;;  
  --launch-instances)  
    launch_instances  
    ;;  
  --stop-instances)  
    stop_instances  
    ;;  
  *)  
    echo "ERROR: Unknown option: $1"  
    show_usage  
    ;;  
esac  

