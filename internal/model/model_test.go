package model

import "testing"

// TestNormalizePath 覆盖 31 的规范化口径：合并重复斜杠、消解 dot segment，
// 并保留结尾斜杠语义。
func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/a/b", "/a/b"},
		{"/a//b", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/../b", "/b"},
		{"/a/b/", "/a/b/"},
		{"/a/b/.", "/a/b"},
		{"/a/b/..", "/a"},
		{"/../a", "/a"},
		{"//", "/"},
		{"/a%2Fb", "/a%2Fb"},
		{"/a/%2e%2e/b", "/a/%2e%2e/b"},
	}
	for _, tc := range cases {
		got, err := NormalizePath(tc.in)
		if err != nil {
			t.Fatalf("NormalizePath(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"/a/%zz", "/a/%2", "/a\x00/b"} {
		if _, err := NormalizePath(bad); err == nil {
			t.Fatalf("NormalizePath(%q) accepted an unsupported path", bad)
		}
	}
}

// TestDecodedPath 确认“先解码再解析”的解释也被覆盖。
func TestDecodedPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/a%2Fb", "/a/b"},
		{"/a/%2e%2e/b", "/b"},
		{"/a/%2E%2E%2Fb", "/b"},
		{"/a/..%2fb", "/b"},
		{"/a%2Fb/", "/a/b/"},
	}
	for _, tc := range cases {
		got, err := DecodedPath(tc.in)
		if err != nil {
			t.Fatalf("DecodedPath(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("DecodedPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestBindingPathAllowedNormalizesBothSides 覆盖 31：判定在规范化形式上做，
// "..", "//", 百分号编码绕过后会逃出前缀的请求一律拒绝。
func TestBindingPathAllowedNormalizesBothSides(t *testing.T) {
	b := Binding{AllowedPaths: []string{"/echo"}}
	allowed := []string{
		"/echo",
		"/echo/",
		"/echo/deep/path",
		"/echo/./deep",
		"/echo/a/../b",
		"/echo//double",
		"/echo/a%2Fb",
	}
	for _, p := range allowed {
		if !b.PathAllowed(p) {
			t.Fatalf("PathAllowed(%q) = false, want true", p)
		}
	}
	rejected := []string{
		"/other",
		"/echo/../admin",
		"/echo/%2e%2e/admin",
		"/echo/..%2fadmin",
		"/echo/%2E%2E%2Fadmin",
		"/echo/a/../../admin",
		"/echo/%zz",
		"/echo\x00/admin",
	}
	for _, p := range rejected {
		if b.PathAllowed(p) {
			t.Fatalf("PathAllowed(%q) = true, want false", p)
		}
	}

	// 空前缀沿用原语义：允许全部路径。
	if !(Binding{}).PathAllowed("/anything/../../else") {
		t.Fatal("empty AllowedPaths must allow every path")
	}
	// 登记的前缀自身也按同一规范化比较。
	c := Binding{AllowedPaths: []string{"/v2/"}}
	if !c.PathAllowed("/v2/objects") || c.PathAllowed("/v2") {
		t.Fatal("trailing slash semantics of the registered prefix changed")
	}
}
