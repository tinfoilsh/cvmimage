package containers

import "testing"

func TestContainersToLaunchExcludesOnlyPreservedContainers(t *testing.T) {
	configured := []Container{{Name: reservedDebugContainerName}, {Name: "app"}}
	launch := containersToLaunch(configured, map[string]bool{reservedDebugContainerName: true})
	if len(launch) != 1 || launch[0].Name != "app" {
		t.Fatalf("containers to launch = %#v", launch)
	}
	if len(configured) != 2 {
		t.Fatalf("configured containers mutated: %#v", configured)
	}
}
