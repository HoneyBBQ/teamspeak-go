package teamspeak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
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

// slog's JSON handler marshals a struct's fields unless the value is a
// LogValuer, and the text handler prints them with %+v; neither may show the
// secret.
func TestSecretsStayOutOfSlog(t *testing.T) {
	values := []any{
		FileUploadInfo{FileTransferKey: "s3cret", Port: 30033},
		FileDownloadInfo{FileTransferKey: "s3cret", Port: 30033},
		PrivilegeKey{Token: "s3cret", Description: "admin"},
		TempPassword{Password: "s3cret", Description: "guest"},
	}
	for _, v := range values {
		for name, newHandler := range map[string]func(*bytes.Buffer) slog.Handler{
			"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
			"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		} {
			var buf bytes.Buffer
			slog.New(newHandler(&buf)).Info("value", "v", v)
			if out := buf.String(); strings.Contains(out, "s3cret") || !strings.Contains(out, "redacted") {
				t.Errorf("%T through the slog %s handler: %s", v, name, out)
			}
		}
	}
}

// json.Marshal is how a caller stores what the server returned; it keeps the
// secret, as documented on each type.
func TestSecretsSurviveJSON(t *testing.T) {
	values := []any{
		FileUploadInfo{FileTransferKey: "s3cret"},
		FileDownloadInfo{FileTransferKey: "s3cret"},
		PrivilegeKey{Token: "s3cret"},
		TempPassword{Password: "s3cret"},
	}
	for _, v := range values {
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal(%T): %v", v, err)
		}
		if !strings.Contains(string(out), "s3cret") {
			t.Errorf("json.Marshal(%T) = %s, want the secret kept", v, out)
		}
	}
}
