# Apple Service Client

A Go library for interacting with Apple's services, including App Store Connect and Developer Portal.

## Features

- Authentication with Apple ID
- Two-factor authentication (2FA) support
- Two-step verification support
- Session management
- Team selection
- Error handling

## Installation

```bash
go get github.com/appuploader/apple-service-v3
```

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/appuploader/apple-service-v3/client"
)

func main() {
	// Create a new client
	c := client.NewClient()

	// Login with your Apple ID
	err := c.Login("your.email@example.com", "your-password")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	// Set your team ID
	err = c.SetTeamID("YOUR_TEAM_ID")
	if err != nil {
		log.Fatalf("Failed to set team ID: %v", err)
	}

	// Use the client...
}
```

## Environment Variables

- `SPACESHIP_SKIP_2FA_UPGRADE`: Set to "1" to automatically bypass 2FA upgrade prompts
- `SPACESHIP_2FA_SMS_DEFAULT_PHONE_NUMBER`: Set to automatically select a phone number for SMS 2FA

## Error Handling

The library provides specific error types for common scenarios:

```go
if err == client.ErrInvalidCredentials {
	// Handle invalid credentials
} else if err == client.ErrInsufficientPermissions {
	// Handle insufficient permissions
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.