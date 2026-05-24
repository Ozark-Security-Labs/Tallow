package evidence

import "testing"

func TestRefValidate(t *testing.T) {
	red := true
	if err := (Ref{ArtifactID: "a", Path: "package/package.json", Excerpt: "name", ExcerptRedacted: &red}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Ref{ArtifactID: "a", Path: "/etc/passwd"}).Validate(); err == nil {
		t.Fatal("want abs path err")
	}
}
