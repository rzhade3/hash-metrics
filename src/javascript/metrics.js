const bcrypt = require('bcrypt');
const crypto = require('crypto');

function calculateAverageHashingTime(saltRounds) {
  const samples = 10; // number of samples to take
  var total_time = 0;
  for (let i = 0; i < samples; i++){
    // Generate a new password on each loop to test the average time
    const plaintextPassword = crypto.randomBytes(32).toString('hex');
    var start = process.hrtime();
    bcrypt.hashSync(plaintextPassword, saltRounds);
    var end = process.hrtime(start);
    total_time += parseHrtimeToSeconds(end);
  }
  return total_time / samples;
}

function parseHrtimeToSeconds(hrtime) {
  var seconds = ((hrtime[0] * 1000000000) + hrtime[1]) / 1000000;
  return seconds;
}

const saltRoundsToEval = [8, 10, 12, 15]

saltRoundsToEval.forEach((saltRounds) => {
  const time = calculateAverageHashingTime(saltRounds);
  console.log(`${saltRounds}, ${time.toFixed(6)} ms`);
});
