const nyanAcceptedParams = {
  message: "from_request"
}

const nyanOutputColumns = [
  "hasNyanCallMe",
  "nyanCallMeType",
  "calledApi",
  "callResult",
  "callError"
]

function main () {
  const nyanCallMeType = typeof nyanCallMe
  const hasNyanCallMe = nyanCallMeType === "function"
  let callResult = null
  let callError = null

  try {
    callResult = nyanCallMe({
      api: "nyan_callme_target",
      caller: "nyan_callme_check",
      message: nyanAllParams.message || "from_check"
    })
  } catch (e) {
    callError = String(e)
  }

  return JSON.stringify({
    success: true,
    status: 200,
    result: {
      hasNyanCallMe: hasNyanCallMe,
      nyanCallMeType: nyanCallMeType,
      calledApi: "nyan_callme_target",
      callResult: callResult,
      callError: callError
    }
  })
}

main()
