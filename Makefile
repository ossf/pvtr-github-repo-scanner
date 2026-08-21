PACKNAME=github-repo
BUILD_FLAGS=-X 'main.GitCommitHash=`git rev-parse --short HEAD`' -X 'main.BuiltAt=`date +%FT%T%z`'
BUILD_WIN=@env GOOS=windows GOARCH=amd64 go build -o $(PACKNAME).exe
BUILD_LINUX=@env GOOS=linux GOARCH=amd64 go build -o $(PACKNAME)
BUILD_MAC=@env GOOS=darwin GOARCH=amd64 go build -o $(PACKNAME)-darwin

COVERAGE = $(shell go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+')

release: package release bin
release-candidate: package release-candidate
binary: package build

release: release-nix release-win release-mac

docker-build: release-nix
	@echo "  >  Building docker image ..."
	@docker build -t $(PACKNAME) .

docker-run:
	@echo "  >  Running docker image ..."
	docker run -it --rm -v ./config.yml:/.privateer/config.yml -v ./docker_output:/evaluation_results $(PACKNAME)

# Pushing to eddieknight docker hub namespace until a more preferred option exists
docker-build-release:
	@echo "  >  Building docker images for linux/amd64 and linux/arm64..."
	docker buildx build --platform linux/amd64,linux/arm64 -t eddieknight/pvtr-github-repo:latest .

docker-run-latest:
	@echo "  >  Running docker image ..."
	docker pull eddieknight/pvtr-github-repo:latest
	docker run -it --rm -v ./config.yml:/.privateer/config.yml -v ./docker_output:/evaluation_results eddieknight/pvtr-github-repo:latest

build:
	@echo "  >  Building binary ..."
	@go build -o $(PACKNAME) -ldflags="$(BUILD_FLAGS)"

package: tidy test
	@echo "  >  Packaging static files..."

vet:
	@echo "  >  Validating code ..."
	@go vet ./...

test: vet
	@go clean -testcache
	@go test ./...

tidy:
	@echo "  >  Tidying go.mod ..."
	@go mod tidy

test-cov: vet
	@echo "Running tests and generating coverage output ..."
	@go test ./... -coverprofile coverage.out -covermode count

print-cov:
	@echo "Current test coverage : $(COVERAGE)%"

release-candidate: tidy test
	@echo "  >  Building release candidate for Linux..."
	$(BUILD_LINUX) -ldflags="$(BUILD_FLAGS) -X 'main.VersionPostfix=nix-rc'"
	@echo "  >  Building release candidate for Windows..."
	$(BUILD_WIN) -ldflags="$(BUILD_FLAGS) -X 'main.VersionPostfix=win-rc'"
	@echo "  >  Building release for Darwin..."
	$(BUILD_MAC) -ldflags="$(BUILD_FLAGS) -X 'main.VersionPostfix=darwin-rc'"

release-nix:
	@echo "  >  Building release for Linux..."
	$(BUILD_LINUX) -ldflags="$(BUILD_FLAGS) -X 'main.VersionPostfix=linux'"

release-win:
	@echo "  >  Building release for Windows..."
	$(BUILD_WIN) -ldflags="$(BUILD_FLAGS) -X 'main.VersionPostfix=windows'"

release-mac:
	@echo "  >  Building release for Darwin..."
	$(BUILD_MAC) -ldflags="$(BUILD_FLAGS) -X 'main.VersionPostfix=darwin'"

bin:
	@echo "  >  Copying binary to ~/.privateer/bin ..."
	@mkdir -p ~/.privateer/bin
	@mv $(PACKNAME)* ~/.privateer/bin
