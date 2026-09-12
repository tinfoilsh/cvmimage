package volume

import "testing"

func TestBackupList(t *testing.T) {
	output := "heading\nSuperblock backups stored on blocks:\n 32768, 98304,\n 163840\n\ntrailer\n"
	if got := backupList(output); got != "  32768, 98304,  163840 " {
		t.Fatalf("backup list: %q", got)
	}
	if got := backupList("missing heading"); got != "" {
		t.Fatal(got)
	}
}
