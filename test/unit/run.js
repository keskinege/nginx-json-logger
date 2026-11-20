import { runTests } from './mock.js';
import { tests } from './tests.js';

async function run(r) {
    const report = await runTests(tests);
    r.headersOut['Content-Type'] = 'application/json';
    r.return(report.failed === 0 ? 200 : 500, JSON.stringify(report));
}

export default { run };
