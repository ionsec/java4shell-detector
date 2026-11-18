//go:build windows

package host

import (
	"golang.org/x/sys/windows/registry"
)

var registryRoots = []string{
	`SOFTWARE\JavaSoft\JDK`,
	`SOFTWARE\JavaSoft\JRE`,
	`SOFTWARE\Eclipse Adoptium\JDK`,
	`SOFTWARE\Amazon Corretto`,
	`SOFTWARE\Azul Systems\Zulu`,
	`SOFTWARE\Microsoft\JDK`,
}

// registryHomes enumerates JavaHome values from the Windows registry.
func registryHomes(goos string) []string {
	if goos != "windows" {
		return nil
	}
	var homes []string
	for _, root := range registryRoots {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := key.ReadSubKeyNames(-1)
		key.Close()
		for _, sub := range names {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, root+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			val, _, err := sk.GetStringValue("JavaHome")
			sk.Close()
			if err == nil && val != "" {
				homes = append(homes, val)
			}
		}
	}
	return homes
}
