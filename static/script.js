document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const resultContainer = document.getElementById('result-container');
    const checkButton = document.getElementById('check-button');

    form.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent the form from reloading the page

        const url = urlInput.value.trim();
        if (!url) return;

        // Disable button and show loading state
        checkButton.disabled = true;
        checkButton.textContent = 'Checking...';
        resultContainer.style.display = 'none';
        resultContainer.className = ''; // Reset classes

        try {
            // Send the URL to our backend API's /predict endpoint
            const response = await fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            if (!response.ok) {
                throw new Error('Network response was not ok.');
            }

            const data = await response.json();
            displayResult(data);

        } catch (error) {
            console.error('Error:', error);
            displayResult({ prediction: 'error' });
        } finally {
            // Re-enable button
            checkButton.disabled = false;
            checkButton.textContent = 'Check URL';
        }
    });

    function displayResult(data) {
        let message = '';
        let resultClass = '';

        switch (data.prediction) {
            case 'benign':
                message = `Result: This URL appears to be safe (Benign).`;
                resultClass = 'result-benign';
                break;
            case 'phishing':
                message = `Warning: This URL is likely a Phishing attempt!`;
                resultClass = 'result-phishing';
                break;
            case 'malicious':
                message = `Danger: This URL is classified as Malicious!`;
                resultClass = 'result-malicious';
                break;
            case 'defacement':
                message = `Notice: This URL is identified as a Defacement site.`;
                resultClass = 'result-defacement';
                break;
            default:
                message = 'Error: Could not process the URL. Please try again.';
                resultClass = 'result-error';
        }

        resultContainer.textContent = message;
        resultContainer.className = resultClass;
        resultContainer.style.display = 'block'; // Make the result visible
    }
});