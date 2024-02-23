# jdxd ⚡️⭐️🔀✨: json data to data

a small program to facilitate codified data-to-data transformation in json-space.

```mermaid
graph TD
    jsonDataIn[JSON Data In] --> optionalInputSchemaValidation{{Optional Input Schema Validation}}
    optionalInputSchemaValidation --> jsonataTransform(JSONata Transform)
    jsonataTransform --> optionalOutputSchemaValidation{{Optional Output Schema Validation}}
    optionalOutputSchemaValidation --> jsonDataOut[JSON Data Out]

    style optionalInputSchemaValidation fill:#c9f9f9,stroke:#333,stroke-width:2px,stroke-dasharray: 5, 5
    style optionalOutputSchemaValidation fill:#c9f9f9,stroke:#333,stroke-width:2px,stroke-dasharray: 5, 5
    style jsonataTransform fill:#ffc,stroke:#333,stroke-width:2px,border-radius:20px
```

in basic usage, it expects to receive a json/jsonnet/jsonl file or input stream, a jsonata transformer, and outputs the transformed result to stdout

you can optionally provide input and output json(net) schemas to be used for pre/post validation
