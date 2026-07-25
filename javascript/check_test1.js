console.log('loaded check_test1.js')

const nyanInputSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  properties: {
    date: {
      type: 'string',
      format: 'date',
      description: '処理対象の日付です。',
      examples: ['2024-06-25']
    }
  },
  additionalProperties: true
}

function main () {
  console.log('nyanAllParams:', nyanAllParams)
  console.log('accepted keys:', nyanAcceptedParamsKeys)
  console.log('nyanErros:', typeof nyanErros)
  console.log('nyanGetAPI:', typeof nyanGetAPI)
  console.log('nyanJsonAPI', typeof nyanJsonAPI)

  return JSON.stringify({ success: true, status: 200 })
}

main()
