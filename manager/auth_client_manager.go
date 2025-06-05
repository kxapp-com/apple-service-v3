package manager

import (
	"sync"

	"github.com/appuploader/apple-service-v3/base"
	"github.com/appuploader/apple-service-v3/idmsa"
	"github.com/appuploader/apple-service-v3/xcode"
)

type AuthClientManager struct {
	authClient  map[string]base.AppleAuthClient
	authApiType map[string]bool
	mu          sync.Mutex
}

var (
	authClientManagerInstance *AuthClientManager
	onceAuthClientManager     sync.Once
)

func GetAuthClientManager() *AuthClientManager {
	onceAuthClientManager.Do(func() {
		authClientManagerInstance = &AuthClientManager{
			authClient:  make(map[string]base.AppleAuthClient),
			authApiType: make(map[string]bool),
		}
	})
	return authClientManagerInstance
}

func (a *AuthClientManager) GetAuthClient(userName string) base.AppleAuthClient {
	a.mu.Lock()
	defer a.mu.Unlock()
	if client, ok := a.authClient[userName]; ok {
		return client
	}
	return nil
}

func (a *AuthClientManager) NewAppleAuthClient(userName string, useXcodeApi bool) base.AppleAuthClient {
	a.mu.Lock()
	defer a.mu.Unlock()
	if client, ok := a.authClient[userName]; ok {
		if a.authApiType[userName] == useXcodeApi {
			return client
		}
	}
	var authClient base.AppleAuthClient
	if useXcodeApi {
		authClient = xcode.NewXcodeAuthClient()
	} else {
		authClient = idmsa.NewDevAuthClient()
	}
	a.authClient[userName] = authClient
	a.authApiType[userName] = useXcodeApi
	return authClient
}
