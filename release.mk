include Makefile

git-version   := $(shell git describe --tags --always --dirty)
dist-sumtypes := .md5 .sha1 .sha256
dist-sumfiles := $(foreach sum,$(dist-sumtypes),$(DIST_ARCHIVES)$(sum))

ifeq ($(git-version),$(PACKAGE_VERSION))
release: $(dist-sumfiles)
	@printf '%s is ready\n' $(PACKAGE_VERSION)
else
release:
	@printf 'Working tree does not match the expected version (%s != %s)\n' \
		$(git-version) $(PACKAGE_VERSION)
	@exit 1
endif

$(dist-sumfiles): $(DIST_ARCHIVES)

%.md5: %
	md5sum $< >$@
%.sha1: %
	sha1sum $< >$@
%.sha256: %
	sha256sum $< >$@

$(DIST_ARCHIVES): distcheck
