//go:build windows

package ipcauth

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openForRead(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

// fileOwnedBy compares the file's owner SID with the caller's. Files an elevated
// process creates are owned by BUILTIN\Administrators rather than by the user,
// but such a caller is privileged and never reaches this check.
func fileOwnedBy(id Identity, f *os.File) (bool, error) {
	// x/sys/windows GetSecurityInfo frees the OS buffer itself and returns a
	// Go-heap copy, so there is nothing to LocalFree here.
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read security info: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return false, fmt.Errorf("read owner: %w", err)
	}

	return id.SID != "" && owner.String() == id.SID, nil
}
