.PHONY: test golden build

build:
	go build -o access-control-helper .

test:
	go test -v -timeout 120s ./...

golden:
	go test -v -run TestScenarios -update -timeout 120s ./...
