// test-upload-debug.js
const testData = {
  title: "Test Record",
  description: "Test description",
  category: "lab_report", 
  fileName: "test.txt",
  fileData: "data:text/plain;base64,VGhpcyBpcyBhIHRlc3QgZmlsZQ==" // "This is a test file" in base64
};

console.log('Test data:', JSON.stringify(testData, null, 2));

// Test the base64 validation
function testBase64Validation() {
  const base64String = testData.fileData;
  const matches = base64String.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
  
  console.log('Base64 validation test:');
  console.log('Matches:', matches);
  console.log('Mime type:', matches[1]);
  console.log('Data length:', matches[2].length);
  
  try {
    const buffer = Buffer.from(matches[2], 'base64');
    console.log('Buffer length:', buffer.length);
    console.log('Buffer content:', buffer.toString());
  } catch (error) {
    console.log('Buffer error:', error.message);
  }
}

testBase64Validation();