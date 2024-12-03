package v1

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testCase struct {
	Input    string
	Expected map[string]struct{}
}

func Test_FindClientSecretMatches(t *testing.T) {
	cases := map[string]testCase{
		// secret
		`secret`: {
			Input:    `"secret": "ljjK-62Q5bJbm43xU5At-NdeWDrhIO_28~",`,
			Expected: map[string]struct{}{"ljjK-62Q5bJbm43xU5At-NdeWDrhIO_28~": {}},
		},

		// client secret
		"client_secret": {
			Input: `    "TenantId": "3d7e0652-b03d-4ed2-bf86-f1299cecde17",
    "ClientSecret": "gHduiL_j6t4b6DG?Qr-G6M@IOS?mX3B9",`,
			Expected: map[string]struct{}{"gHduiL_j6t4b6DG?Qr-G6M@IOS?mX3B9": {}},
		},
		"client secret at end": {
			Input: `secret: UAByAGkAbQBhAHIAeQAgAEsAZQB5AA==`,
			Expected: map[string]struct{}{
				"UAByAGkAbQBhAHIAeQAgAEsAZQB5AA==": {},
			},
		},
		"client_secret1": {
			Input: `   public static string clientId = "413ff05b-6d54-41a7-9271-9f964bc10624";
        public static string clientSecret = "k72~odcN_6TbVh5D~19_1Qkj~87trteArL";

        private const string `,
			Expected: map[string]struct{}{"k72~odcN_6TbVh5D~19_1Qkj~87trteArL": {}},
		},
		"client_secret2": {
			Input: `    "azClientSecret": "2bWD_tu3~9B0_.R0W3BFJN-Hu_xjfR8EL5",
    "kvVaultUri": "https://corp.vault.azure.net/",`,
			Expected: map[string]struct{}{"2bWD_tu3~9B0_.R0W3BFJN-Hu_xjfR8EL5": {}},
		},
		"client_secret3": {
			Input: `# COMMAND ----------

clientID = "193e3d24-8d04-404c-95a9-074efaa83147"
tenantID = "28241a04-7ac0-44f1-a996-84dc181f9861"
secret = "a2djRWTXDS1iMbThoK.C7e:yVsUdL3[:"`,
			Expected: map[string]struct{}{"a2djRWTXDS1iMbThoK.C7e:yVsUdL3[:": {}},
		},
		"client_secret4": {
			Input: `tenantID = "9f37a392-g0ae-1280-9796-f1864210effc"
secret = "s.1_56k~5jmRDm23y.dTg5_XjTAcRjCbH."

# COMMAND ----------

configs = {"fs.azure.account.auth.type": "OAuth"`,
			Expected: map[string]struct{}{"s.1_56k~5jmRDm23y.dTg5_XjTAcRjCbH.": {}},
		},
		"client_secret5": {
			Input: `public class HardcodedAzureCredentials {
	private final String clientId = "81734019-15a3-50t8-3253-5abe78abc3a1";
	private final String username = "username@example.onmicrosoft.com";
	private final String clientSecret = "1n1.qAc~3Q-1t38aF79Xzv5AUEfR5-ct3_";`,
			Expected: map[string]struct{}{"1n1.qAc~3Q-1t38aF79Xzv5AUEfR5-ct3_": {}},
		},
		// https://github.com/kedacore/keda/blob/main/pkg/scalers/azure_log_analytics_scaler_test.go
		"client_secret6": {
			Input: `const (
	tenantID                    = "d248da64-0e1e-4f79-b8c6-72ab7aa055eb"
	clientID                    = "41826dd4-9e0a-4357-a5bd-a88ad771ea7d"
	clientSecret                = "U6DtAX5r6RPZxd~l12Ri3X8J9urt5Q-xs"
	workspaceID                 = "074dd9f8-c368-4220-9400-acb6e80fc325"`,
			Expected: map[string]struct{}{"U6DtAX5r6RPZxd~l12Ri3X8J9urt5Q-xs": {}},
		},
		"client_secret7": {
			Input: `  "AZUREAD-AKS-APPID-SECRET": "xW25Gt-Mf0.ue3jFqE68jtFqtt-4L_8R51",
  "AZUREAD-AKS-TENANTID": "d3a761f8-e7ea-473a-b907-1e7b3ef92aa9",`,
			Expected: map[string]struct{}{"xW25Gt-Mf0.ue3jFqE68jtFqtt-4L_8R51": {}},
		},
		"client_secret8": {
			Input:    ` "AZUREAD-AKS-APPID-SECRET": "8w__IGsaY.6g6jUxb1.pPGK262._pgX.q-",`,
			Expected: map[string]struct{}{"8w__IGsaY.6g6jUxb1.pPGK262._pgX.q-": {}},
		},
		"client_secret9": {
			Input: `      client-id: 49abd816-45d1-479a-b49a-80bcf6d7213a
      client-secret: 7.18gt1b2wO-t.~Cf.mlZCyHC7r_micnuO`,
			Expected: map[string]struct{}{"7.18gt1b2wO-t.~Cf.mlZCyHC7r_micnuO": {}},
		},
		"client_secret10": {
			Input:    `    "aadClientSecret": "6p3t93TJzPgsNtQISqWc.-@?GCz9-ZWo",`,
			Expected: map[string]struct{}{"6p3t93TJzPgsNtQISqWc.-@?GCz9-ZWo": {}},
		},
		"client_secret11": {
			Input: `CLIENT_ID=9f5a8591-20b9-46b3-8317-9cc2cd52ca76
CLIENT_SECRET=2XlwmIlo3XkjE1@y[cuWsPj3_N@F23F/
TENANT_ID=08c43a10-b16a-426e-b7e8-b3b42a60e181`,
			Expected: map[string]struct{}{"2XlwmIlo3XkjE1@y[cuWsPj3_N@F23F/": {}},
		},

		"password": {
			Input: `# Login using Service Principal
$ApplicationId = "5cec5dfb-0ac4-4938-b477-3f9638881b93"
$SecuredPassword = ConvertTo-SecureString -String "gHduiL_j6t4b6DG?Qr-G6M@IOS?mX3B9" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPassword`,
			Expected: map[string]struct{}{"gHduiL_j6t4b6DG?Qr-G6M@IOS?mX3B9": {}},
		},

		// False positives
		"invalid - placeholder_secret": {
			Input: `- Log in with a service principal using a client secret:

az login --service-principal --username {{http://azure-cli-service-principal}} --password {{secret}} --tenant {{someone.onmicrosoft.com}}`,
		},

		"invalid -  only alpha characters": {
			Input: `"passwordCredentials":[],"preferredTokenSigningKeyThumbprint":null,"publisherName":"Microsoft"`,
		},
		"invalid - low entropy": {
			Input: `clientSecret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		},
		"invalid - passwordCredentials1": {
			Input: `"passwordCredentials":[{"customKeyIdentifier":"UAByAGkAbQBhAHIAeQAgAEsAZQB5AA==","endDate":"2019-07-16T23:01:19.028Z","keyId":`,
		},
		"invalid - passwordCredentials2": {
			Input: `"passwordCredentials":[{"customKeyIdentifier":"TQB5ACAARgBpAHIAcwB0ACAASwBlAHkA"`,
		},
		"invalid - passwordCredentials3": {
			Input: `,"passwordCredentials":[{"customKeyIdentifier":"awBlAHkAZgBvAHIAaQBtAHAAYQBsAGEA",`,
		},
		"invalid - azure vault path": {
			Input: `        public const string MsalArlingtonOBOKeyVaultUri = "https://msidlabs.vault.azure.net:443/secrets/ARLMSIDLAB1-IDLASBS-App-CC-Secret";`,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			matches := findSecretMatches(test.Input)
			if len(matches) == 0 {
				if len(test.Expected) != 0 {
					t.Fatalf("no matches found, expected: %v", test.Expected)
					return
				} else {
					return
				}
			}

			if diff := cmp.Diff(test.Expected, matches); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", name, diff)
			}
		})
	}
}
