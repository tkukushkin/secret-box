//go:build darwin

package secretbox

import "github.com/keybase/go-keychain"

// KeychainProvider abstracts macOS Keychain operations.
type KeychainProvider interface {
	Get(service, account string) []byte
	Set(data []byte, service, account string) error
	Delete(service, account string)
}

// SystemKeychain provides real macOS Keychain access.
type SystemKeychain struct{}

func (k SystemKeychain) Get(service, account string) []byte {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil || len(results) == 0 {
		return nil
	}
	return results[0].Data
}

func (k SystemKeychain) Set(data []byte, service, account string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	item.SetData(data)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)

	return keychain.AddItem(item)
}

func (k SystemKeychain) Delete(service, account string) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(account)
	_ = keychain.DeleteItem(item)
}
