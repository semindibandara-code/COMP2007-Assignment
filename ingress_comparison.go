package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type IngressFrame struct {
	IP    string
	Port  int
	Proto string
}

func parseIngressFrame(rawStr string) (*IngressFrame, error) {
	if rawStr == "" {
		return nil, errors.New("FrameError: Empty ingress payload")
	}
	parts := strings.Split(rawStr, ",")
	if len(parts) < 3 {
		return nil, errors.New("FrameError: Incomplete frame delimiters")
	}
	portNum, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, errors.New("FrameError: Malformed numeric port")
	}
	return &IngressFrame{IP: parts[0], Port: portNum, Proto: parts[2]}, nil
}

func main() {
	frame, err := parseIngressFrame("10.0.0.1,80,TCP")
	if err != nil {
		fmt.Printf("Ingress dropped: %v\n", err)
		return
	}
	fmt.Printf("Processing payload directed to port: %d\n", frame.Port)
}
