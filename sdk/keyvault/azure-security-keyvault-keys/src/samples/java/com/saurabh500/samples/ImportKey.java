package com.saurabh500.samples;

import javax.crypto.spec.SecretKeySpec;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

public class ImportKey {

	public static void main(String[] args) throws InterruptedException, IllegalArgumentException {

        // Instantiate a key client that will be used to call the service. Notice that the client is using default Azure
        // credentials. To make default credentials work, ensure that environment variables 'AZURE_CLIENT_ID',
        // 'AZURE_CLIENT_KEY' and 'AZURE_TENANT_ID' are set with the service principal credentials.
        
        String keyVaultName = System.getenv("KEY_VAULT_NAME");
        String kvUri = "https://" + keyVaultName + ".vault.azure.net";
        
        KeyClient client = new KeyClientBuilder().vaultUrl(kvUri)
        		.credential(new DefaultAzureCredentialBuilder().build()).buildClient();
        
        byte[] symmetrickeyContent = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
        
        String keyName = "importedSymmetricKey";
        KeyVaultKey importResult = client.importKey(keyName, JsonWebKey.fromAes(new SecretKeySpec(symmetrickeyContent, "AES")));
        System.out.printf("Imported Key Id: %s Name : %s Version = %s\n", importResult.getId(), 
        		importResult.getName());
        
        KeyVaultKey keyvaultKey = client.getKey(keyName);
        System.out.printf("Key Retrieved by name with version %s ", keyvaultKey.getProperties().getVersion());

    }
}
