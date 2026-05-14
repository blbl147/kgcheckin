import { spawn } from 'child_process'

function delay(ms) {
  return new Promise(resolve => {
    setTimeout(resolve, ms)
  })
}

// 运行api服务
function startService() {

  let api = spawn("npm", ["run", "apiService"])

  api.stdout.on('data', data => {
    // console.log(`${data}`)
  })

  api.on('close', code => {
    console.log(`子进程退出`)
  })
  api.stderr.on('data', data => {
    console.log("服务启动失败")
    throw new Error(`${data}`)
  })
  return api

}

// 关闭api服务
function close_api(api) {
  api.kill()
}

// 发送请求
async function send(path, method, headers) {
  const result = await fetch("http://127.0.0.1:3000" + path, {
    method: method,
    headers: headers
  }).then(r => r.json())
  // console.log(result)
  return result
}

export { delay, startService, close_api, send }
