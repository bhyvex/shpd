TAG=${TAG:-latest}
IMAGE=shipyard/shpd
COMMIT=`git rev-parse --short HEAD`

all: deps build media

deps:
	@godep restore

clean:
	@rm -rf Godeps/_workspace shpd

build:
	@godep go build -ldflags "-w -X github.com/shipyard/shpd/version.GitCommit $(COMMIT)" .

media:
	@cd static && bower -s install --allow-root -p | xargs echo

image: media build
	@echo Building image $(TAG)
	@docker build -t $(IMAGE):$(TAG) .

release: deps build image
	@docker push $(IMAGE):$(TAG)

test: clean 
	@godep go test -v ./...

.PHONY: all deps build clean media image test release
