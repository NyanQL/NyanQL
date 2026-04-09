const nyanAcceptedParams = {
  caller: "nyan_callme_check",
  message: "from_check"
}

const nyanOutputColumns = ["called_api", "echo"]

function main () {
  return JSON.stringify({
    success: true,
    status: 200,
    called_api: nyanAllParams.api,
    echo: {
      caller: nyanAllParams.caller || null,
      message: nyanAllParams.message || null
    }
  })
}

main()
