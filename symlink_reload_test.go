package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type symlinkReloadFixture struct {
	rootPath, linkPath, firstPath, secondPath, apiName string
}

func newSymlinkReloadFixture(t *testing.T, included bool) symlinkReloadFixture {
	t.Helper()
	dir := t.TempDir()
	fixture := symlinkReloadFixture{
		rootPath: filepath.Join(dir, "api.json"), linkPath: filepath.Join(dir, "current.json"),
		firstPath: filepath.Join(dir, "v1.json"), secondPath: filepath.Join(dir, "v2.json"),
		apiName: "item",
	}
	writeTestFile(t, fixture.firstPath, `{"item":{"description":"initial"}}`)
	writeTestFile(t, fixture.secondPath, `{"item":{"description":"initial"}}`)
	replaceTestSymlink(t, fixture.linkPath, "v1.json")
	if included {
		writeTestFile(t, fixture.rootPath, `{"sub":{"type":"include","path":"current.json"}}`)
		fixture.apiName = "sub/item"
	} else {
		fixture.rootPath = fixture.linkPath
	}
	return fixture
}

func replaceTestSymlink(t *testing.T, linkPath, target string) {
	t.Helper()
	temporary := linkPath + ".next"
	if err := os.Symlink(target, temporary); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if err := os.Rename(temporary, linkPath); err != nil {
		t.Fatalf("replace symlink: %v", err)
	}
}

func TestReloadAPIConfigGraphRetargetsRootAndIncludeSymlinks(t *testing.T) {
	for _, included := range []bool{false, true} {
		name := "root"
		if included {
			name = "include"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newSymlinkReloadFixture(t, included)
			initial := loadTestAPIConfig(t, fixture.rootPath)
			setTestAPISnapshot(t, initial.Snapshot)
			// The bytes are identical, but subsequent edits must follow the new target.
			replaceTestSymlink(t, fixture.linkPath, "v2.json")
			if err := verifyAPIFileStates(initial.Snapshot.Files); err == nil {
				t.Fatal("retargeted symlink was accepted as the original file state")
			}
			observed, reloaded, err := reloadAPIConfigGraphIfChanged(fixture.rootPath, initial.Snapshot.Files)
			if err != nil || !reloaded {
				t.Fatalf("retarget with identical content: reloaded=%t err=%v", reloaded, err)
			}
			writeTestFile(t, fixture.firstPath, `{"item":{"description":"old target changed"}}`)
			observed, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
			if err != nil || reloaded {
				t.Fatalf("unreferenced old target triggered reload: reloaded=%t err=%v", reloaded, err)
			}
			writeTestFile(t, fixture.secondPath, `{"item":{"description":"new target changed"}}`)
			_, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
			if err != nil || !reloaded {
				t.Fatalf("new target edit: reloaded=%t err=%v", reloaded, err)
			}
			if got := currentSQLFiles()[fixture.apiName].Description; got != "new target changed" {
				t.Fatalf("description=%q, want new target changed", got)
			}
		})
	}
}

func TestReloadAPIConfigGraphWatchesEachSymlinkToSharedTarget(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "api.json")
	firstLink := filepath.Join(dir, "first.json")
	secondLink := filepath.Join(dir, "second.json")
	writeTestFile(t, rootPath, `{"first":{"type":"include","path":"first.json"},"second":{"type":"include","path":"second.json"}}`)
	writeTestFile(t, filepath.Join(dir, "shared.json"), `{"item":{"description":"shared"}}`)
	writeTestFile(t, filepath.Join(dir, "new.json"), `{"item":{"description":"new"}}`)
	replaceTestSymlink(t, firstLink, "shared.json")
	replaceTestSymlink(t, secondLink, "shared.json")
	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)

	replaceTestSymlink(t, firstLink, "new.json")
	observed, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("retarget first alias: reloaded=%t err=%v", reloaded, err)
	}
	if currentSQLFiles()["first/item"].Description != "new" || currentSQLFiles()["second/item"].Description != "shared" {
		t.Fatal("retargeting one alias did not preserve the other mount")
	}
	writeTestFile(t, filepath.Join(dir, "shared.json"), `{"item":{"description":"shared updated"}}`)
	_, reloaded, err = reloadAPIConfigGraphIfChanged(rootPath, observed)
	if err != nil || !reloaded {
		t.Fatalf("edit remaining shared target: reloaded=%t err=%v", reloaded, err)
	}
	if currentSQLFiles()["first/item"].Description != "new" || currentSQLFiles()["second/item"].Description != "shared updated" {
		t.Fatal("remaining alias no longer follows its target")
	}
}

func TestReloadAPIConfigGraphSymlinkFailureRetainsSnapshotAndRecovers(t *testing.T) {
	for _, included := range []bool{false, true} {
		name := "root"
		if included {
			name = "include"
		}
		for _, failure := range []string{"missing", "invalid", "cycle"} {
			t.Run(name+"/"+failure, func(t *testing.T) {
				fixture := newSymlinkReloadFixture(t, included)
				initial := loadTestAPIConfig(t, fixture.rootPath)
				setTestAPISnapshot(t, initial.Snapshot)
				badPath := filepath.Join(filepath.Dir(fixture.linkPath), "bad.json")
				wantError := "file not found"
				switch failure {
				case "invalid":
					writeTestFile(t, badPath, `{"broken":`)
					wantError = ""
				case "cycle":
					writeTestFile(t, badPath, `{"again":{"type":"include","path":"current.json"}}`)
					wantError = "cycle"
				}
				replaceTestSymlink(t, fixture.linkPath, "bad.json")
				observed, reloaded, err := reloadAPIConfigGraphIfChanged(fixture.rootPath, initial.Snapshot.Files)
				if err == nil || !strings.Contains(err.Error(), wantError) || reloaded {
					t.Fatalf("invalid target: reloaded=%t err=%v, want error containing %q", reloaded, err, wantError)
				}
				if currentAPISnapshot() != initial.Snapshot {
					t.Fatal("failed reload replaced the active snapshot")
				}
				observed, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
				if err != nil || reloaded {
					t.Fatalf("unchanged failed target was retried: reloaded=%t err=%v", reloaded, err)
				}
				if failure == "missing" {
					// A dangling link must also recover when its target is created.
					writeTestFile(t, badPath, `{"item":{"description":"recovered"}}`)
				} else {
					// Keep the bad target unchanged and recover by switching the link.
					writeTestFile(t, fixture.secondPath, `{"item":{"description":"recovered"}}`)
					replaceTestSymlink(t, fixture.linkPath, "v2.json")
				}
				_, reloaded, err = reloadAPIConfigGraphIfChanged(fixture.rootPath, observed)
				if err != nil || !reloaded {
					t.Fatalf("recovery: reloaded=%t err=%v", reloaded, err)
				}
				if got := currentSQLFiles()[fixture.apiName].Description; got != "recovered" {
					t.Fatalf("description=%q, want recovered", got)
				}
			})
		}
	}
}

func TestReloadAPIConfigGraphRetargetsDirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "current")
	rootPath := filepath.Join(linkPath, "api.json")
	for _, version := range []string{"v1", "v2"} {
		writeTestFile(t, filepath.Join(dir, version, "api.json"), `{"sub":{"type":"include","path":"child.json"}}`)
		writeTestFile(t, filepath.Join(dir, version, "child.json"), `{"item":{"description":"`+version+`"}}`)
	}
	replaceTestSymlink(t, linkPath, "v1")
	initial := loadTestAPIConfig(t, rootPath)
	setTestAPISnapshot(t, initial.Snapshot)
	replaceTestSymlink(t, linkPath, "v2")
	_, reloaded, err := reloadAPIConfigGraphIfChanged(rootPath, initial.Snapshot.Files)
	if err != nil || !reloaded {
		t.Fatalf("directory symlink switch: reloaded=%t err=%v", reloaded, err)
	}
	if got := currentSQLFiles()["sub/item"].Description; got != "v2" {
		t.Fatalf("description=%q, want v2", got)
	}
}
