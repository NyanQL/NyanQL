const nyanOutputSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  properties: {
    success: { const: true },
    status: { const: 200 },
    result: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          today_count: { type: 'integer' }
        },
        required: ['today_count'],
        additionalProperties: false
      }
    },
    api: { type: 'string' }
  },
  required: ['success', 'status', 'result', 'api'],
  additionalProperties: false
}

const output = JSON.parse(nyanAllParams.nyan_output.body)

if (
  output.success === true &&
  output.status === 200 &&
  Array.isArray(output.result) &&
  typeof output.api === 'string'
) {
  ({ success: true, status: 200 })
} else {
  ({
    success: false,
    status: 500,
    result: { message: 'test2の出力形式が不正です。' }
  })
}
