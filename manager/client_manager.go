package manager

import (
	"github.com/kxapp-com/apple-service-v3/base"
	"github.com/kxapp-com/apple-service-v3/idmsa"
	"github.com/kxapp-com/apple-service-v3/xcode"
	"sync"
)

type ClientManager struct {
	appleClient   map[string]base.AppleClient
	clientApiType map[string]bool
	mu            sync.Mutex
}

var (
	clientManagerInstance *ClientManager
	onceClientManager     sync.Once
)

func GetClientManager() *ClientManager {
	onceClientManager.Do(func() {
		clientManagerInstance = &ClientManager{
			appleClient:   make(map[string]base.AppleClient),
			clientApiType: make(map[string]bool),
		}
	})
	return clientManagerInstance
}

func (c *ClientManager) GetClient(userName string) base.AppleClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.appleClient[userName]; ok {
		return client
	}
	return nil
}

func (c *ClientManager) NewAppleClient(userName string, useXcodeApi bool) base.AppleClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.appleClient[userName]; ok {
		if c.clientApiType[userName] == useXcodeApi {
			return client
		}
	}
	var appleClient base.AppleClient
	if useXcodeApi {
		appleClient = xcode.NewXcodeClient(userName)
	} else {
		appleClient = idmsa.NewDevClient(userName)
	}
	c.appleClient[userName] = appleClient
	c.clientApiType[userName] = useXcodeApi
	return appleClient
}
