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

schemas/%.json: generators/%.jsonnet
	$(call render_jsonnet,$<,$@)

# generate json schemas from jsonnet
schemas: schemas/FileToJsonataTransformerMapping.schema.json schemas/FileToValidatedInOutTransformerMapping.schema.json

# build the binary
jdxd:
	go build
