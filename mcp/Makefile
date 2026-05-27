.PHONY: policy
policy:
	@cp ../policy/policy.toml internal/policy/policy.toml
	@expected=$$(shasum -a 256 ../policy/policy.toml | awk '{print $$1}'); \
	 actual=$$(shasum -a 256 internal/policy/policy.toml | awk '{print $$1}'); \
	 if [ "$$expected" != "$$actual" ]; then \
	   echo "policy.toml SHA mismatch — refusing to build"; exit 1; \
	 fi

.PHONY: build
build: policy
	go build ./...

.PHONY: test
test:
	go test ./...

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: vet
vet:
	go vet ./...
