package app

import "time"

func restartDelayForFailures(failures int) time.Duration {
	switch {
	case failures <= 1:
		return 2 * time.Second
	case failures == 2:
		return 5 * time.Second
	case failures == 3:
		return 10 * time.Second
	case failures == 4:
		return 20 * time.Second
	case failures == 5:
		return 30 * time.Second
	default:
		return 60 * time.Second
	}
}
