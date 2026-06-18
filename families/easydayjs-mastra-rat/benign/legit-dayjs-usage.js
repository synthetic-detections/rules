// Legitimate dayjs usage — should NOT trigger any easy-day-js rules
const dayjs = require('dayjs');
const utc = require('dayjs/plugin/utc');
const timezone = require('dayjs/plugin/timezone');

dayjs.extend(utc);
dayjs.extend(timezone);

const now = dayjs().tz('America/New_York');
console.log(now.format('YYYY-MM-DD HH:mm:ss'));

// Using detached child processes for legitimate purposes
const { spawn } = require('child_process');
const child = spawn('node', ['worker.js'], {
    detached: true,
    stdio: 'ignore'
});
child.unref();
