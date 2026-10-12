package teamspeak

import (
	"fmt"
	"strings"
	"testing"
)

func TestSecretsStayOutOfFormatting(t *testing.T) {
	values := []any{
		Request{command: "clientmove", params: []param{strArg("cpw", "s3cret")}, passwords: []string{"cpw"}},
		FileUploadInfo{FileTransferKey: "s3cret", Port: 30033},
		FileDownloadInfo{FileTransferKey: "s3cret", Port: 30033},
		PrivilegeKey{Token: "s3cret"},
		TempPassword{Password: "s3cret"},
	}
	for _, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, "s3cret") {
				t.Errorf("%T formatted with %s leaks the secret: %s", v, verb, out)
			}
			if out := fmt.Sprintf(verb, &v); strings.Contains(out, "s3cret") {
				t.Errorf("*%T formatted with %s leaks the secret: %s", v, verb, out)
			}
		}
	}
}
