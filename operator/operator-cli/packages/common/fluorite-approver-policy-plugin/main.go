package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/cmd"
	"github.com/cert-manager/approver-policy/pkg/registry"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/nacl/sign"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	name     = "fluorite-approver-policy-plugin"
	readyKey = "ready"
)

func main() {
	cmd.ExecutePolicyApprover()
}

// Ensure that example plugin gets registered with the shared registry
func init() {
	registry.Shared.Store(&examplePlugin{})
}

// examplePlugin is an implementation of approver-policy.Interface
// https://github.com/cert-manager/approver-policy/blob/v0.6.3/pkg/approver/approver.go#L27-L53
type examplePlugin struct {
	// whether a CertificateRequestPolicy without this plugin defined should
	// be allowed
	// policyWithNoPluginAllowed                 bool
	attestation_transparency_service_endpoint          string
	attestation_transparency_service_endpoint_password string
	attestationBytes                                   []byte
	privateKeyBytes                                    (*[64]byte)
	enqueueChan                                        <-chan string
	log                                                logr.Logger
}

var _ approver.Interface = &examplePlugin{}

func (e *examplePlugin) Name() string {
	return name
}

func (e *examplePlugin) RegisterFlags(fs *pflag.FlagSet) {
	fs.StringVar(&e.attestation_transparency_service_endpoint, "attestation-transparency-service-endpoint", "", "The Endpoint of the Attestation Transparency Service where CSR are sent (ex. https://example.com:8080/verify_csr)")
	fs.StringVar(&e.attestation_transparency_service_endpoint_password, "attestation-transparency-service-endpoint-password", "", "The Password for accessing Endpoint of the Attestation Transparency Service where CSR are sent")
	// fs.BoolVar(&e.policyWithNoPluginAllowed, "policy-with-no-plugin-allowed", true, "Whether a CertificateRequestPolicy without example-approver-policy plugin should be allowed in the cluster")
}

// Prepare is called once when the approver plugin is being initialized and before the controllers have started.
// https://github.com/cert-manager/approver-policy/blob/v0.6.3/pkg/internal/cmd/cmd.go#L86
func (e *examplePlugin) Prepare(ctx context.Context, log logr.Logger, mgr manager.Manager) error {
	e.log = log.WithName(name)
	// The example plugin does not utilize this channel
	e.enqueueChan = make(<-chan string)

	attestationBytes, err := os.ReadFile("/etc/approver-policy/secrets/attestation")
	if err != nil {
		return fmt.Errorf("error reading /etc/approver-policy/secrets/attestation: %v", err)
	}
	// e.log.V(5).Info("attestation", "hex", hex.EncodeToString(attestationBytes))
	e.attestationBytes = attestationBytes

	privateKeyBytes, err := os.ReadFile("/etc/approver-policy/secrets/signature-private-key")
	if err != nil {
		return fmt.Errorf("error reading /etc/approver-policy/secrets/signature-private-key: %v", err)
	}
	// e.log.V(5).Info("signature-private-key", "hex", hex.EncodeToString(privateKeyBytes))
	e.privateKeyBytes = (*[64]byte)(privateKeyBytes)

	if e.attestation_transparency_service_endpoint == "" {
		return fmt.Errorf("the Attestation Transparency Service endpoint is empty")
	}
	_, err = url.Parse(e.attestation_transparency_service_endpoint)
	if err != nil {
		return fmt.Errorf("error parsing the Attestation Transparency Service endpoint %s : %v", e.attestation_transparency_service_endpoint, err)
	}

	if e.attestation_transparency_service_endpoint_password == "" {
		return fmt.Errorf("the secret for accessing the Attestation Transparency Service endpoint is empty")
	}

	return nil
}

func (e *examplePlugin) ReadyCheck(crp *policyapi.CertificateRequestPolicy) (bool, string) {
	plugin, ok := crp.Spec.Plugins[name]
	if !ok {
		msg := fmt.Sprintf("required plugin %s is not defined", name)
		return false, msg
	}
	val := plugin.Values[readyKey]
	ready, err := strconv.ParseBool(val)
	if err != nil {
		msg := fmt.Sprintf("Invalid ready value \"%s\", cannot be converted to bool", val)
		return false, msg
	}

	if !ready {
		msg := fmt.Sprintf("Ready value is not set to true: %s", val)
		return false, msg
	}
	return true, ""

}

func (e *examplePlugin) CustomLogic(cr *cmapi.CertificateRequest) (bool, string) {
	e.log.V(5).Info("the certificate request ", "b64", base64.StdEncoding.EncodeToString(cr.Spec.Request))

	csrPEM := cr.Spec.Request

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		msg := "Failed to parse csr PEM"
		return false, msg
	}

	cert, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse certificate: %v.", err)
		return false, msg
	}
	// https://www.rfc-editor.org/rfc/rfc9525#appendix-A-2.2
	// The server identity can only be expressed in the subjectAltNames extension;
	// it is no longer valid to use the commonName RDN, known as CN-ID
	//
	// For this reason we won't check the presence of a commonName field and/or its value

	if len(cert.DNSNames) != 1 {
		msg := fmt.Sprintf("There should be at least one, and only one Subject Alternate Name DNSNames values: %v.", cert.DNSNames)
		return false, msg
	}
	domain_name := cert.DNSNames[0]

	signed_csr := sign.Sign(nil, csrPEM, e.privateKeyBytes)

	signed_csr_b64 := base64.StdEncoding.EncodeToString(signed_csr)
	attestation_b64 := base64.StdEncoding.EncodeToString(e.attestationBytes)

	data := map[string]string{"signed_csr_b64": signed_csr_b64, "attestation_b64": attestation_b64, "domain": domain_name}
	json_data, err := json.Marshal(data)

	if err != nil {
		msg := fmt.Sprintf("Error converting to json the signed_csr_b64 and attestation_b64 map: %v.", err)
		return false, msg
	}

	e.log.V(5).Info("json to be sent", "json", json_data)

	req, err := http.NewRequest("POST", e.attestation_transparency_service_endpoint, bytes.NewBuffer(json_data))
	if err != nil {
		msg := fmt.Sprintf("Error creating request: %v", err)
		return false, msg
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", e.attestation_transparency_service_endpoint_password))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		msg := fmt.Sprintf("Error sending post request to Attestation Transparency Service: %v.", err)
		return false, msg
	}
	defer resp.Body.Close()
	resBody, err := io.ReadAll(resp.Body)

	if err != nil {
		msg := fmt.Sprintf("Error reading body of the response of the post request to Attestation Transparency Service: %v.", err)
		return false, msg
	}

	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("The Attestation Transparency Service did not answer with a StatusCode of 200 (OK): %s, %v.", resp.Status, string(resBody))
		return false, msg
	}

	var resBodyJson map[string]bool

	err = json.Unmarshal(resBody, &resBodyJson)
	if err != nil {
		msg := fmt.Sprintf("Error unmarshaling response from Attestation Transparency Service: %v.", err)
		return false, msg
	}

	success, exists := resBodyJson["success"]
	if !exists || !success {
		msg := fmt.Sprintf("The operation in the Attestation Transparency Service failed: (exists) %v : (success) %v.", exists, success)
		return false, msg
	}
	return true, ""
}

// Evaluate will be called when a CertificateRequest is synced with each
// combination of the CertifiateRequest and an applicable
// CertificateRequestPolicy that has this plugin enabled.
// For any combination:
// - If Evaluate returns an error, the CertificateRequest will not be denied or
// approved and will be resynced.
// - If Evalute returns Denied, the CertificateRequest will be Denied.
// - If Evaluate returns Approved and all other relevant plugins (including core
// approver in cert-manager/approver-policy) also return Approved, the
// CertificateRequst will be approved.
// https://github.com/cert-manager/approver-policy/blob/v0.6.3/pkg/internal/approver/manager/review.go#L128
func (e *examplePlugin) Evaluate(ctx context.Context, crp *policyapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
	e.log.V(5).Info("evaluating CertificateRequest", "certificaterequest", cr.Name, "certificaterequestpolicy", crp.Name)

	ready, err_msg := e.ReadyCheck(crp)
	if !ready {
		return approver.EvaluationResponse{Result: approver.ResultDenied, Message: err_msg}, nil
	}

	success, error_msg := e.CustomLogic(cr)
	if !success {
		return approver.EvaluationResponse{Result: approver.ResultDenied, Message: error_msg}, nil

	} else {
		return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: ""}, nil
	}

	// if d < 0 || d > 6 {
	// 	msg := fmt.Sprintf("Invalid weekday %d, days have to be in range from 0 (Sunday) to 6 (Saturday)", d)
	// 	return approver.EvaluationResponse{Result: approver.ResultDenied, Message: msg}, nil
	// }
	// allowedDay := time.Weekday(d)
	// today := time.Now().Weekday()
	// if allowedDay != today {
	// 	msg := fmt.Sprintf("Issuance only allowed on %s today is %s", allowedDay.String(), today.String())
	// 	return approver.EvaluationResponse{Result: approver.ResultDenied, Message: msg}, nil
	// }
	// return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: ""}, nil
}

// Validate will be run by the approver-policy's admission webhook.
// https://github.com/cert-manager/approver-policy/blob/v0.6.3/deploy/charts/approver-policy/templates/webhook.yaml#L22-L52
// An error returned here will result in failed creation of update of the
// CertificateRequestPolicy being validated.
func (e *examplePlugin) Validate(ctx context.Context, policy *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
	e.log.V(5).Info("validating CertificateRequestPolicy", "certificaterequestpolicy", policy.Name)

	ready, err_msg := e.ReadyCheck(policy)
	if !ready {
		e := fmt.Errorf("%s", err_msg)
		return approver.WebhookValidationResponse{Allowed: false, Errors: []*field.Error{}}, e
	} else {
		return approver.WebhookValidationResponse{Allowed: true, Errors: nil}, nil
	}

}

// Ready will be called every time a CertificateRequestPolicy is reconciled in
// response to events against CertificateRequestPolicy as well as events sent by
// the plugin via EnqueueChan. CertificateRequestPolicy's Ready status is set
// depending on the response returned by Ready methods of applicable plugins
// (including core approver) - if any returns false, Ready status will be false.
// https://github.com/cert-manager/approver-policy/blob/v0.6.3/pkg/internal/controllers/certificaterequestpolicies.go#L184
func (e *examplePlugin) Ready(ctx context.Context, crp *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
	e.log.V(5).Info("validating that CertificateRequestPolicy is ready", "certificaterequestpolicy", crp.Name)

	ready, err_msg := e.ReadyCheck(crp)
	if !ready {
		e := fmt.Errorf("%s", err_msg)
		return approver.ReconcilerReadyResponse{Ready: false, Errors: []*field.Error{}}, e
	} else {
		return approver.ReconcilerReadyResponse{Ready: true}, nil
	}
}

// EnqueueChan returns a channel to which the plugin can send applicable
// CertificateRequestPolicy names to cause them to be resynced. This is useful
// if readiness of CertificateRequestPolicies with the plugin enabled needs to
// be re-evaluated in response to changes in some external system used by the
// plugin.
func (e *examplePlugin) EnqueueChan() <-chan string {
	return e.enqueueChan
}
