# Automates https://learn.microsoft.com/en-us/azure/container-apps/custom-domains-managed-certificates?pivots=azure-cli
RESOURCE_GROUP=$1
CONTAINER_APP=$2
CONTAINER_APP_ENV=$3
ZONE_NAME=$4
A_RECORD_NAME=$5
TXT_RECORD_NAME="asuid.$A_RECORD_NAME"            
DOMAIN_NAME="$A_RECORD_NAME.$ZONE_NAME"

# 1. Set minium/maxium number of replicas to 1 so it's always running
az containerapp update \
    -n $CONTAINER_APP \
    -g $RESOURCE_GROUP \
    --cpu 0.5 \
    --memory 1.0Gi \
    --min-replicas 1 \
    --max-replicas 1

# 2. If you're configuring an apex domain, get the IP address of your Container Apps environment.
IP=$(az containerapp env show \
    -n $CONTAINER_APP_ENV \
    -g $RESOURCE_GROUP \
    --query "properties.staticIp" \
    -o tsv)

# 3. Get the domain verification code.
DOMAIN_VERIFICATION_ID=$(az containerapp show \
                        -n $CONTAINER_APP \
                        -g $RESOURCE_GROUP \
                        -o tsv \
                        --query "properties.customDomainVerificationId")

# 4. Using the DNS provider that is hosting your domain, create DNS records based on the record type 
# you selected using the values shown in the Domain validation section. The records point the 
# domain to your container app and verify that you own it.
#     If you selected A record, create the following DNS records:
#     Record type 	Host 	Value
#     A 	@ 	The IP address of your Container Apps environment.
#     TXT 	asuid 	The domain verification code.

# 5. Remove old TXT record
az network dns record-set txt delete \
    -g $RESOURCE_GROUP \
    -n $TXT_RECORD_NAME \
    --zone-name $ZONE_NAME \
    --yes

# 6. Add the TXT record for verification
az network dns record-set txt add-record \
    -g $RESOURCE_GROUP \
    --zone-name $ZONE_NAME \
    --record-set-name $TXT_RECORD_NAME \
    --value $DOMAIN_VERIFICATION_ID

# 7. Remove old A record
az network dns record-set a delete \
    -g $RESOURCE_GROUP \
    -n $A_RECORD_NAME \
    --zone-name $ZONE_NAME \
    --yes

# 8. Add the A record for the Container APP
az network dns record-set a add-record \
    -g $RESOURCE_GROUP \
    --zone-name $ZONE_NAME \
    --record-set-name $A_RECORD_NAME \
    --ipv4-address $IP \
    --ttl 3600

# 9. Add the domain to your container app.
az containerapp hostname add \
    --hostname $DOMAIN_NAME \
    -g $RESOURCE_GROUP \
    -n $CONTAINER_APP

# 10. Configure the managed certificate and bind the domain to your container app.
az containerapp hostname bind \
    --hostname $DOMAIN_NAME \
    -g $RESOURCE_GROUP \
    -n $CONTAINER_APP \
    --environment $CONTAINER_APP_ENV \
    --validation-method HTTP
