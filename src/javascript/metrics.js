const bcrypt = require('bcrypt');
const crypto = require('crypto');
var pbkdf2 = require('pbkdf2')

const SAMPLES = 10; // number of samples to take

function parseHrtimeToSeconds(hrtime) {
  var seconds = ((hrtime[0] * 1000000000) + hrtime[1]) / 1000000;
  return seconds;
}

function calculateAverageHashingTime(samples, algorithm, iterations) {
  var total_time = 0;
  for (let i = 0; i < samples; i++){
    total_time += algorithm(iterations);
  }
  return total_time / samples;
}

function getHashingAlgorithm(algorithm) {
  algos = {
    "pbkdf2-sha256": benchmarkPbkdf2Sha2,
    "pbkdf2-sha512": benchmarkPbkdf2Sha5,
    "bcrypt": benchmarkBcrypt
  }
  if (!(algorithm in algos)) {
    throw new Error("Invalid algorithm: " + algorithm);
  }
  return algos[algorithm]
}

/*
  Hashing algorithms
*/

function benchmarkBcrypt(saltRounds) {
  // Generate a new password on each loop to test the average time
  const plaintextPassword = crypto.randomBytes(32).toString('hex');
  var start = process.hrtime();
  bcrypt.hashSync(plaintextPassword, saltRounds);
  var end = process.hrtime(start);
  return parseHrtimeToSeconds(end);
}

function benchmarkPbkdf2Sha2(iterations) {
  // Generate a new password on each loop to test the average time
  const plaintextPassword = crypto.randomBytes(32).toString('hex');
  const salt = crypto.randomBytes(8).toString('hex');
  var start = process.hrtime();
  pbkdf2.pbkdf2Sync(plaintextPassword, salt, iterations, 64, 'sha256');
  var end = process.hrtime(start);
  return parseHrtimeToSeconds(end);
}

function benchmarkPbkdf2Sha5(iterations) {
  // Generate a new password on each loop to test the average time
  const plaintextPassword = crypto.randomBytes(32).toString('hex');
  const salt = crypto.randomBytes(8).toString('hex');
  var start = process.hrtime();
  pbkdf2.pbkdf2Sync(plaintextPassword, salt, iterations, 64, 'sha512');
  var end = process.hrtime(start);
  return parseHrtimeToSeconds(end);
}

function main(algorithm, iterations) {
  var algorithm = getHashingAlgorithm(algorithm);
  var results = {}
  iterations.forEach((iteration) => {
    results[iteration] = calculateAverageHashingTime(SAMPLES, algorithm, iteration);
  });
  return results;
}

var iterations = process.argv.slice(3).map(x => parseInt(x));
results = main(process.argv[2], iterations);
console.log(results);
