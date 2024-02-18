{
  '$schema': 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  additionalProperties: false,
  properties: {
    'in': {
      type: 'object',
      description: 'input json schema definition',
    },
    jsonata: {
      type: 'string',
      description: 'transformer jsonata definition',
    },
    // hold on this support
    // jsonnet: {
    //   type: 'string',
    //   description: 'transformer jsonata definition',
    // },
    out: {
      type: 'object',
      description: 'output json schema definition',
    },
  },
  oneOf: [
    {
      required: ['jsonata'],
    },
    // {
    //   required: ['jsonnet'],
    // },
  ],
}
