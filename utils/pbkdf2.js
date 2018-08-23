const {pbkdf2: pbkdf2Async, pbkdf2Sync} = require('pbkdf2')

const promisifiedPbkdf2 = (password, salt, iterations, length, algo) =>
  new Promise((resolveFunction, rejectFunction) => {
    pbkdf2Async(password, salt, iterations, length, algo, (error, response) => {
      if (error) {
        rejectFunction(error)
      }
      resolveFunction(response)
    })
  })

const pbkdf2 = async (password, salt, iterations, length, algo) => {
  try {
    const result = await promisifiedPbkdf2(password, salt, iterations, length, algo)
    return result
  } catch (e) {
    // falback to sync since on Firefox promisifiedPbkdf2 fails for empty password
    return pbkdf2Sync(password, salt, iterations, length, algo)
  }
}

module.exports = pbkdf2
