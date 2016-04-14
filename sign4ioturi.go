// Add a method for SigV4 signing of AWS IoT-Data MQTT-over-WebSocket URI.
// May be generalizeable to other services, or combine-able with S3 URI-signing,
// but the variability of SigV4 among services makes this tricky or inelegant.
package awsauth

import (
	"fmt"
	"net/url"
	"strings"
)

// Prints debug-information (
var DEBUG_SignUrl bool = true

//TODO: consider a SignUrl(), e.g.: higher level for this function and SignS3Url()
// But... SignS3Url wants a http.Request, which is not meaningful for IoT-Data wss://... URIs
// S3 URIs SigV4'd with query-string uses incompatible

// Take a bare URI and make a signed URI from it
// Input: something like...
//   wss://ABCD1234EFGH56.iot.us-east-1.amazonaws.com/mqtt
// Output: something like...
//   wss://ABCD1234EFGH56.iot.us-east-1.amazonaws.com/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...
func Sign4WSIoTDataURL(rawURI string, credentials ...Credentials) string {
	// Pull apart URI for pre-specified query-string
	u, err := url.Parse(rawURI)
	if err != nil {
		fmt.Println(err)
	}

	// Disassemble host; narrow in scope: Verify service and auto-detect region.
	// Generalization is tricky because needs lookup ("data.iot" OR "ABCD[...].iot"=>"iotdata")
	// Host looks something like ABCD1234EFGH56.iot.us-east-1.amazonaws.com
	splitURI := strings.Split(u.Host, ".")
	service := "iotdata"
	region := splitURI[2]
	if splitURI[1] != "iot" {
		errStr := fmt.Sprintf("ERROR: Sign4WSIoTDataURL works only for IoT-Data service; got service=%q from %q", service, u.Host)
		fmt.Sprintf(errStr)
		return errStr
	}

	// Assemble Credential: <your-access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request
	algName := "AWS4-HMAC-SHA256"
	keys := chooseKeys(credentials)
	timestamp := timestampV4()
	date := tsDateV4(timestamp)
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)
	credString := fmt.Sprintf("%s/%s", keys.AccessKeyID, scope)

	// Pass-through any query params (should be none?) and add new ones.
	q := u.Query()
	q.Set("X-Amz-Algorithm", algName)
	q.Set("X-Amz-Credential", credString)
	q.Set("X-Amz-Date", timestamp)
	//q.Set("X-Amz-Expires", "86400") // Unused for iotdata, but might be needed for other services...?
	q.Set("X-Amz-SignedHeaders", "host")

	// Dump each individual element
	if DEBUG_SignUrl {
		fmt.Println("Signed Query elements are:")
		for k, v := range q {
			fmt.Printf("  %20s=%v\n", k, v)
		}
	}

	// Assemble Canonical Request (TM)... which is otherwise unused.
	// Adapted from canonical example in JavaScript at
	// http://docs.aws.amazon.com/iot/latest/developerguide/protocols.html
	u.RawQuery = q.Encode()
	canReq := fmt.Sprintf("GET\n%s\n%s\nhost:%s\n\nhost\n%s",
		u.Path,                 // "/mqtt"
		q.Encode(),             // list of query-strings that are signed
		u.Host,                 // e.g., [...].iot.us-east-1.amazonaws.com
		hashSHA256([]byte("")), //"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	// Assemble String To Sign (TM)
	hashCanReq := hashSHA256([]byte(canReq))
	signMe := fmt.Sprintf("%s\n%s\n%s\n%s", algName, timestamp, scope, hashCanReq)

	// Sign it
	signingKey := signingKeyV4(keys.SecretAccessKey, date, region, service)
	signatureVal := signatureV4(signingKey, signMe)

	// Append additional query-strings
	// These depend on above and are not signed for IoT-Data service; must manually construct and append.
	// Security-Token is Base64, so must be escaped.
	finalURI := fmt.Sprintf("%s&%s=%s&%s=%s",
		u.String(),
		"X-Amz-Signature", signatureVal,
		"X-Amz-Security-Token", url.QueryEscape(keys.SecurityToken),
	)

	// Dump debugging information if requested
	if DEBUG_SignUrl {
		fmt.Println("****************************************")
		fmt.Println("DEBUG INFO FOR Sign4WSIoTDataURL:")
		fmt.Println("Original URI:", rawURI)
		fmt.Println("Canonical Request is...")
		fmt.Println("----------------------------------------")
		fmt.Println(canReq)
		fmt.Println("----------------------------------------")
		fmt.Println("String To Sign is...")
		fmt.Println("----------------------------------------")
		fmt.Println(signMe)
		fmt.Println("----------------------------------------")
		fmt.Println("Final URI:")
		fmt.Println(finalURI)
		fmt.Println("****************************************")
	}
	return finalURI
}
