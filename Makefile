help:
	@cat Makefile \
	| grep -B1 -h -E "^[a-zA-Z0-9_-]+:([^\=]|$$)" \
	| grep -v -- -- \
	| grep -v '^help' \
	| sed 'N;s/\n/###/' \
	| sed -n 's/^# \(.*\)###\(.*\):.*/\2###\1/p' \
	| column -t  -s '###' \
	| cat


# usage: $(call render_jsonnet,$<,$@)
define render_jsonnet
	test -d $(dir $2) || mkdir -p $(dir $2)
	jsonnet $1 | jq -S | tee $2
endef

cmd/jdxd/schemas/%.json: generators/%.jsonnet
	$(call render_jsonnet,$<,$@)

# generate json schemas from jsonnet
schemas: \
	cmd/jdxd/schemas/InXfmOutSpec.schema.json \
	cmd/jdxd/schemas/FileToJsonataTransformerMapping.schema.json \
	cmd/jdxd/schemas/FileToValidatedInOutTransformerMapping.schema.json

pkg/jdxd/runnable.go: schemas/InXfmOutSpec.schema.json
	go-jsonschema -p jdxd $< | tee $@

# build the binary
build:
	go -o jdxd build cmd/jdxd/main.go
