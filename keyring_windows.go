// +build windows

package keyring

import (
	"github.com/danieljoos/wincred"
)

type winProvider struct {
}

func (p *winProvider) Get(Service, Username string) (string, error) {
	cred1, err := wincred.GetGenericCredential(fmt.Sprintf("%s/%s", Service, Username))
	if err == nil && cred1.UserName == Username {
		return string(cred1.CredentialBlob), nil
	}

	return "", ErrNotFound
}

func (p *winProvider) Set(Service, Username, Password string) error {
	cred := wincred.NewGenericCredential(fmt.Sprintf("%s/%s", Service, Username))
	cred.UserName = Username
	cred.CredentialBlob = []byte(Password)
	return cred.Write()
}

func initializeProvider() (provider, error) {
	return &winProvider{}, nil
}
