package teamspeak

import "testing"

// The answer carries an ip when the file transfer is not reachable at the
// address the connection uses. No server measured here sent one, so the row is
// built from the key alone.
func TestInitFileUpload_ReadsTheIP(t *testing.T) {
	s := &script{replies: []reply{{rows: []map[string]string{{
		"clientftfid": "1", "serverftfid": "6", "ftkey": "itRNdsIOvcBiBg/Xj4Ge51ZSrsShHuid", "port": "30033",
		"seekpos": "0", "proto": "0", "ip": "10.0.0.7",
	}}}}}
	info, err := NewCommands(s).InitFileUpload(t.Context(), 5, "/image.iso", 3, FileUploadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "10.0.0.7" || info.Port != 30033 {
		t.Errorf("info = %+v, want ip 10.0.0.7 and port 30033", info)
	}
}

// Measured on both servers, which send no ip when the file transfer port is
// reachable where the connection is; the download row carries one as the
// upload's would.
func TestInitFileTransfer_NoIPIsEmpty(t *testing.T) {
	up := &script{replies: []reply{{rows: []map[string]string{{
		"clientftfid": "5", "ftkey": "ZxCyLsM8mXYr3DWwWgr64A9eqkdm6DgK", "port": "20033", "proto": "0",
		"seekpos": "0", "serverftfid": "1",
	}}}}}
	upInfo, err := NewCommands(up).InitFileUpload(t.Context(), 2, "/ctw.bin", 3, FileUploadOptions{})
	if err != nil || upInfo.IP != "" {
		t.Errorf("upload = %+v, %v, want no ip", upInfo, err)
	}

	down := &script{replies: []reply{{rows: []map[string]string{{
		"clientftfid": "6", "ftkey": "C0Cl9TnLIZrQw8ejoVpfTkSh0HVTmroC", "port": "20033", "proto": "0",
		"serverftfid": "2", "size": "3", "ip": "192.0.2.9",
	}}}}}
	downInfo, err := NewCommands(down).InitFileDownload(t.Context(), 2, "/ctw.bin", FileDownloadOptions{})
	if err != nil || downInfo.IP != "192.0.2.9" || downInfo.Size != 3 {
		t.Errorf("download = %+v, %v", downInfo, err)
	}
}
