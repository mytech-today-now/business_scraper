// Quick debug script to test validation function
const { ValidationService } = require('./src/utils/validation.ts')

const validationService = new ValidationService()

console.log('Testing sanitizeInput function:')

const test1 = 'Hello<>{}[]|\\World'
const result1 = validationService.sanitizeInput(test1)
console.log(`Input: "${test1}"`)
console.log(`Output: "${result1}"`)
console.log(`Expected: "Hello&lt;&gt;{}[]|\\World"`)
console.log('---')

const test2 = 'Hello & "World" <script>'
const result2 = validationService.sanitizeInput(test2)
console.log(`Input: "${test2}"`)
console.log(`Output: "${result2}"`)
console.log(`Expected: "Hello &amp; &quot;World&quot; &lt;script&gt;"`)
console.log('---')

const test3 = 'onclick="alert(1)" onload="malicious()"'
const result3 = validationService.sanitizeInput(test3)
console.log(`Input: "${test3}"`)
console.log(`Output: "${result3}"`)
console.log(`Expected: " "`)
