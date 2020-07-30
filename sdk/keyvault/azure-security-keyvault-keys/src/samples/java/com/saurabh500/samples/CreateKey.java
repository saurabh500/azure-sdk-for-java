package com.saurabh500.samples;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;
import com.azure.security.keyvault.keys.models.CreateKeyOptions;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

public class CreateKey {

	public static void main(String[] args) throws InterruptedException, IllegalArgumentException {

        // Instantiate a key client that will be used to call the service. Notice that the client is using default Azure
        // credentials. To make default credentials work, ensure that environment variables 'AZURE_CLIENT_ID',
        // 'AZURE_CLIENT_KEY' and 'AZURE_TENANT_ID' are set with the service principal credentials.
        
        String keyVaultName = System.getenv("KEY_VAULT_NAME");
        String kvUri = "https://" + keyVaultName + ".vault.azure.net";
        
        KeyClient client = new KeyClientBuilder().vaultUrl(kvUri)
        		.credential(new DefaultAzureCredentialBuilder().build()).buildClient();
        
        
        String keyName = "somekey";
//        KeyVaultKey importResult = client.importKey(keyName, JsonWebKey.fromAes(new SecretKeySpec(symmetrickeyContent, "AES")));
//        System.out.printf("Imported Key Id: %s Name : %s Version = %s\n", importResult.getId(), 
//        		importResult.getName());
        boolean create = false;
		if (create) {
			CreateKeyOptions ckOptions = new CreateKeyOptions(keyName, KeyType.RSA);
			KeyVaultKey createKey = client.createKey(ckOptions);
			System.out.printf("Imported Key Id: %s Name : %s \n", createKey.getId(), createKey.getName());
		}

        byte[] symmetrickeyContent = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        KeyVaultKey keyvaultKey = client.getKey(keyName);
        System.out.printf("Key Retrieved by name with version %s ", keyvaultKey.getProperties().getVersion());

        CryptographyClient cryptoClient = new CryptographyClientBuilder()
                .credential(new DefaultAzureCredentialBuilder().build())
                .keyIdentifier(keyvaultKey.getId())
                .buildClient();

        WrapResult result = cryptoClient.wrapKey(KeyWrapAlgorithm.RSA_OAEP_256, symmetrickeyContent);
        byte[] encryptedKeyBytes = result.getEncryptedKey();
        
        UnwrapResult unwrapResult = cryptoClient.unwrapKey(result.getAlgorithm(), encryptedKeyBytes);
        
        byte[] unwrappedResult = unwrapResult.getKey();
        
        System.out.println("The lengths are "+ unwrappedResult.length + " and " + symmetrickeyContent.length);
        for(int i = 0 ; i < unwrappedResult.length; i++) {
        	if(i > symmetrickeyContent.length || unwrappedResult[i] != symmetrickeyContent[i]) {
        		System.out.println("something broke");
        		break;
        	}
        }
        
    }
}
