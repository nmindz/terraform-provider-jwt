package jwt

import (
	"encoding/json"
	"fmt"

	jwtgen "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceHashedToken() *schema.Resource {
	return &schema.Resource{
		Create: createHashedJWT,
		Delete: deleteHashedJWT,
		Read:   readHashedJWT,

		Schema: map[string]*schema.Schema{
			"algorithm": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HS512",
				Description:  "Signing algorithm to use",
				ValidateFunc: validateHashingAlgorithm,
				ForceNew:     true,
			},
			"secret": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "HMAC secret to sign the JWT with",
				ForceNew:    true,
				Sensitive:   true,
			},
			"claims_json": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The token's claims, as a JSON document",
				ForceNew:    true,
			},
			"token": &schema.Schema{
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
		},
	}
}

func createHashedJWT(d *schema.ResourceData, meta interface{}) (err error) {
	alg := d.Get("algorithm").(string)
	signer := jwtgen.GetSigningMethod(alg)

	claims := d.Get("claims_json").(string)

	jsonClaims := make(map[string]interface{})
	json.Unmarshal([]byte(claims), &jsonClaims)

	token := jwtgen.NewWithClaims(signer, jwtgen.MapClaims(jsonClaims))

	secret := d.Get("secret").(string)

	hashedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return err
	}
	compactClaims, _ := json.Marshal(token.Claims)
	d.SetId(string(compactClaims))
	d.Set("token", hashedToken)
	return
}

func deleteHashedJWT(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func readHashedJWT(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func validateHashingAlgorithm(iAlg interface{}, k string) (warnings []string, errs []error) {
	alg, ok := iAlg.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string", k))
		return
	}
	method := jwtgen.GetSigningMethod(alg)
	if method == nil {
		errs = append(errs, fmt.Errorf("%s is not a supported signing algorithim. Choices are HS256, HS384, HS512", alg))
		return
	}
	if _, isHMAC := method.(*jwtgen.SigningMethodHMAC); !isHMAC {
		errs = append(errs, fmt.Errorf("For RSA/ECDSA signing, please use the jwt_signed_token resource"))
	}
	return
}
