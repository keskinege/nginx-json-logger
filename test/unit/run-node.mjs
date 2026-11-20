import { runTests } from './mock.js';
import { tests } from './tests.js';

const report = await runTests(tests);
console.log(JSON.stringify(report, null, 2));
process.exit(report.failed === 0 ? 0 : 1);
