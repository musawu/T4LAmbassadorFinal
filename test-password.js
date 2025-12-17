require('dotenv').config();

console.log('Testing password...');
console.log('Password from .env:', process.env.EMAIL_PASSWORD);

// Check if it matches what was shown
const expected = 'gimr iczu mwnj ytoq';
const actual = process.env.EMAIL_PASSWORD;

if (actual === expected) {
  console.log('✅ Password CORRECT!');
} else {
  console.log('❌ Password WRONG!');
  console.log('Expected:', expected);
  console.log('Actual:  ', actual);
  console.log('\n🔧 Fix: Update .env with: EMAIL_PASSWORD=gimr iczu mwnj ytoq');
}
