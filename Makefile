# robinet build targets. Linux only, that is the whole target platform:
# a hub on a public address, a tenant daemon on a workstation or VM, and a
# connector in a container.

GO       ?= go
# A tag, exactly, when this commit is one and the tree is clean. Otherwise the
# last tag with a UTC timestamp, so a binary from dist is never mistaken for a
# release and two builds made an hour apart never claim to be the same thing.
TAGGED   := $(shell git describe --tags --exact-match 2>/dev/null)
DIRTY    := $(shell git status --porcelain 2>/dev/null | head -1)
VERSION  ?= $(if $(and $(TAGGED),$(if $(DIRTY),,x)),$(TAGGED),$(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)-dev-$(shell date -u +%m%d%H%M%S))
PKG      := github.com/rjsocha/robinet
LDBASE   := -s -w -X $(PKG)/internal/version.Build=$(VERSION)
LDFLAGS  := -ldflags=$(LDBASE)

# Every directory under variant/ holding a config.json produces its own binary
# with that configuration linked in.
VARIANTS := $(patsubst variant/%/config.json,%,$(wildcard variant/*/config.json))
SRC      := ./cmd/robinet
DIST     := dist
GOFLAGS  := CGO_ENABLED=0

# The hopper package ships one preconfigured variant, for people who should
# not have to be told a url and a token.
IMAGE          ?= wyga/robinet
IMAGE_TAG      ?= 1

# The variant is whoever is distributing this: a directory under variant/ that
# is not in git, because it carries a hub and a token.
HOPPER_VARIANT ?= internal

# Where the package goes. Deliberately empty: a channel belongs to whoever
# publishes, not to this repository, and naming one here would put somebody's
# infrastructure in a public file. Set it in the environment.
HOPPER_TO      ?=
ARTIFACTS      := .artifacts

.PHONY: all build local amd64 variants docker docker-push hopper hopper-channel hopper-stage hopper-file test race vet fmt fmt-check tidy clean hashes version install

all: build

# Everything we ship, which is linux/amd64 and nothing else: the hub, the
# machines it serves and the platforms the connector runs on are all that, and
# an architecture nobody builds for is an architecture nobody tests.
build: amd64

amd64:
	$(GOFLAGS) GOOS=linux GOARCH=amd64 $(GO) build "$(LDFLAGS)" -o $(DIST)/linux/amd64/robinet $(SRC)

# Preconfigured builds for internal distribution: the binary already knows its
# hub and token, so a person runs one command instead of copying a url and a
# secret out of a message. It grants nothing: the ssh key still decides.
variants: $(addprefix variant-,$(VARIANTS))
	@test -n "$(VARIANTS)" || echo "no variants: add variant/<name>/config.json"

variant-%:
	@test -f variant/$*/config.json || { \
	  echo "variant/$*/config.json is missing."; \
	  echo "It carries the hub token, so it is not in git: copy variant/example/config.json"; \
	  echo "and fill in the hub, the token and whatever note should be shown."; \
	  exit 1; \
	}
	@$(GOFLAGS) GOOS=linux GOARCH=amd64 $(GO) build \
	  "-ldflags=$(LDBASE) -X $(PKG)/internal/variant.Name=$* -X $(PKG)/internal/variant.Encoded=$$(base64 -w0 variant/$*/config.json)" \
	  -o $(DIST)/linux/amd64/robinet.variant.$* $(SRC)
	@echo "built $(DIST)/linux/amd64/robinet.variant.$*"

# ----- connector image --------------------------------------------------

# The connector runs in a container inside the network being exposed, so this
# is how most people will ever run robinet.
docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(IMAGE_TAG) .
	@echo "built $(IMAGE):$(IMAGE_TAG)"

# Pushes what is already built, so what goes out is what was tested here.
docker-push:
	@docker image inspect $(IMAGE):$(IMAGE_TAG) >/dev/null 2>&1 || \
	  { echo "$(IMAGE):$(IMAGE_TAG) is not built: make docker"; exit 1; }
	docker push $(IMAGE):$(IMAGE_TAG)

# ----- hopper package ---------------------------------------------------

# Stage exactly what hopper.json expects, from the variant build.
hopper-stage: hopper-channel variant-$(HOPPER_VARIANT)
	@mkdir -p $(ARTIFACTS)
	cp $(DIST)/linux/amd64/robinet.variant.$(HOPPER_VARIANT) $(ARTIFACTS)/robinet-linux-amd64
	@echo "staged $(ARTIFACTS)/robinet-linux-amd64 from variant $(HOPPER_VARIANT)"

hopper-channel:
	@test -n "$(HOPPER_TO)" || { \
	  echo "HOPPER_TO is not set: it names the channel to publish to,"; \
	  echo "for example HOPPER_TO=<channel>:/hopper/package/robinet make hopper"; \
	  exit 1; \
	}

# Build the package and push it. Pushing is the point, so this is the one
# target that reaches outside this machine.
hopper: hopper-stage
	ROBINET_RELEASE=$(VERSION) hopper publish --to $(HOPPER_TO)

# Same package, written to a tarball instead of pushed. For checking the
# manifest without publishing anything.
hopper-file: hopper-stage
	ROBINET_RELEASE=$(VERSION) hopper publish --to $(HOPPER_TO) --to-file $(ARTIFACTS)/robinet-package.tar

# Host platform only, for fast iteration.
local:
	$(GOFLAGS) $(GO) build "$(LDFLAGS)" -o $(DIST)/$(shell $(GO) env GOOS)/$(shell $(GO) env GOARCH)/robinet $(SRC)

# Drop the binary where it can be run without a path.
install:
	$(GOFLAGS) $(GO) install "$(LDFLAGS)" $(SRC)

# ----- checks -----------------------------------------------------------

test:
	$(GO) test ./...

# The enrollment path spans three goroutine owners, so the race detector
# earns its runtime here.
race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not gofmt clean:"; echo "$$out"; exit 1; fi

# ----- housekeeping -----------------------------------------------------

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(DIST) $(ARTIFACTS)

hashes:
	@find $(DIST) -type f -exec sha256sum {} \;

version:
	@echo $(VERSION)
