package event

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func honeytokenTouched() *Event {
	e := New(ClassFileSystemActivity, FileRead, SeverityHigh, at)
	e.Message = "おとりの認証情報が読まれました"
	e.Device = &Device{UID: "pc-001", Hostname: "pc-001"}
	e.File = &File{Name: "credentials", Path: "/home/user/.aws/credentials"}
	e.Actor = &Actor{Process: &Process{PID: 4242, Name: "cat", CmdLine: "cat /home/user/.aws/credentials"}}
	return e
}

func TestNew(t *testing.T) {
	e := New(ClassProcessActivity, ProcessLaunch, SeverityInformational, at)
	if e.CategoryUID != 1 {
		t.Errorf("category_uid = %d, 期待値 1", e.CategoryUID)
	}
	if e.TypeUID != 100701 {
		t.Errorf("type_uid = %d, 期待値 100701", e.TypeUID)
	}
	if e.Time != at.UnixMilli() {
		t.Errorf("time = %d, 期待値 %d", e.Time, at.UnixMilli())
	}
	if e.Metadata.UID == "" || e.Metadata.UID == New(ClassProcessActivity, ProcessLaunch, SeverityInformational, at).Metadata.UID {
		t.Error("イベントの ID が空か、重複している")
	}
}

func TestValidate(t *testing.T) {
	if err := honeytokenTouched().Validate(); err != nil {
		t.Fatalf("正しいイベントが拒否された: %v", err)
	}

	tests := []struct {
		name   string
		modify func(*Event)
		want   string
	}{
		{"不明なクラス", func(e *Event) { e.ClassUID = 9999 }, "不明なクラス"},
		{"カテゴリーの不一致", func(e *Event) { e.CategoryUID = 4 }, "category_uid"},
		{"type_uid の不一致", func(e *Event) { e.TypeUID = 1 }, "type_uid"},
		{"時刻なし", func(e *Event) { e.Time = 0 }, "time"},
		{"重大度が範囲外", func(e *Event) { e.SeverityID = 7 }, "severity_id"},
		{"ID なし", func(e *Event) { e.Metadata.UID = "" }, "metadata"},
		{"ファイルなし", func(e *Event) { e.File = nil }, "file"},
		{"端末なし", func(e *Event) { e.Device = nil }, "device"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := honeytokenTouched()
			tt.modify(e)
			err := e.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("エラー = %v, %q を含むはず", err, tt.want)
			}
		})
	}
}

func TestRequiredFieldsPerClass(t *testing.T) {
	tests := []struct {
		class    ClassUID
		activity int
		fill     func(*Event)
	}{
		{ClassProcessActivity, ProcessLaunch, func(e *Event) {
			e.Device = &Device{UID: "pc-001"}
			e.Process = &Process{PID: 1, Name: "sh"}
		}},
		{ClassDetectionFinding, FindingCreate, func(e *Event) {
			e.FindingInfo = &FindingInfo{UID: "f-1", Title: "ハートビートの途絶"}
		}},
		{ClassNetworkActivity, NetworkOpen, func(e *Event) {
			e.SrcEndpoint = &Endpoint{IP: "192.0.2.10", Port: 50000}
			e.DstEndpoint = &Endpoint{IP: "198.51.100.1", Port: 443}
		}},
		{ClassDNSActivity, DNSActivityQuery, func(e *Event) {
			e.Query = &DNSQuery{Hostname: "example.jp", Type: "A"}
		}},
		{ClassDHCPActivity, DHCPAssign, func(e *Event) {
			e.DstEndpoint = &Endpoint{IP: "192.0.2.20", MAC: "02:00:00:00:00:01"}
		}},
	}
	for _, tt := range tests {
		e := New(tt.class, tt.activity, SeverityInformational, at)
		if err := e.Validate(); err == nil {
			t.Errorf("クラス %d: 必須項目なしで検証に通った", tt.class)
		}
		tt.fill(e)
		if err := e.Validate(); err != nil {
			t.Errorf("クラス %d: %v", tt.class, err)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	e := honeytokenTouched()
	e.Unmapped = map[string]any{"honeytoken_id": "aws-1"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"class_uid":1001`, `"type_uid":100102`, `"device":{"uid":"pc-001"`, `"actor":{"process"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("JSON に %s が含まれない: %s", key, data)
		}
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&got, e) {
		t.Errorf("読み直したイベントが一致しない\n got: %+v\nwant: %+v", got, *e)
	}
}
