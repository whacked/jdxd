{
  type: 'object',
  patternProperties: {
    '^.+$': {
      type: ['object', 'null'],
      required: ['inputSchema', 'transformer', 'outputSchema'],
      properties: {
        inputSchema: {
          type: 'object',
        },
        transformer: {
          type: 'string',
        },
        outputSchema: {
          type: 'object',
        },
      },
    },
  },
}
