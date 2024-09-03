import validateStrict from '@secvisogram/csaf-validator-lib/validateStrict.js'
import * as mandatory from '@secvisogram/csaf-validator-lib/mandatoryTests.js'
import * as optional from '@secvisogram/csaf-validator-lib/optionalTests.js'
import { csaf_2_0_strict } from '@secvisogram/csaf-validator-lib/schemaTests.js'
import { createRequire } from "module";
const require = createRequire(import.meta.url);

const document = require(process.argv[2])
const tests = [
    csaf_2_0_strict,
    ...Object.values(mandatory),
    ...Object.values(optional),
]
const result = await validateStrict(tests, document)
if (!result.isValid) {
    for (const test of result.tests) {
        if (test.isValid) continue
        console.log(test.name+" failed:")
        for (const error of test.errors) {
            console.log(error)
        }
    }
    process.exit(1)
}