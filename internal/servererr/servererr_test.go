package servererr_test

import (
	"testing"

	"github.com/honeybbq/teamspeak-go/errcode"
	"github.com/honeybbq/teamspeak-go/internal/servererr"
)

func TestParse(t *testing.T) {
	err := servererr.Parse(map[string]string{
		"id": "2568", "msg": "insufficient client permissions", "failed_permid": "236", "extra_msg": "detail",
	})
	if err.Code != errcode.PermissionsClientInsufficient || err.FailedPermID != 236 || err.ExtraMessage != "detail" {
		t.Errorf("parsed %+v", err)
	}
	if err.FailedPermission != "" {
		t.Errorf("an id-only line named the permission %q", err.FailedPermission)
	}
	named := servererr.Parse(map[string]string{
		"id": "2568", "msg": "insufficient client permissions", "failed_permission": "b_serverinstance_info_view",
	})
	if named.FailedPermission != "b_serverinstance_info_view" || named.FailedPermID != 0 {
		t.Errorf("parsed %+v, want the name and no id", named)
	}
	if servererr.Parse(map[string]string{"id": "0", "msg": "ok"}) != nil {
		t.Error("id=0 is success")
	}
	got := servererr.Parse(map[string]string{"msg": "no id"})
	if got == nil || got.Code != errcode.Undefined {
		t.Errorf("an error line without an id = %v, want errcode.Undefined", got)
	}
}
