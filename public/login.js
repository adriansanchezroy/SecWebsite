const loginForm = document.getElementById('login');
const submitButton = loginForm.querySelector('button[type="submit"]');

loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    // Disable the submit button to prevent repeated login attempts
    submitButton.disabled = true;

    const formData = new FormData(loginForm);
    const username = formData.get('username');
    const password = formData.get('password');

    const data = {
      username: username,
      password: password,
    };

    try {
      const response = await fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      if (response.status === 200) {
        submitButton.disabled = false;
        window.location.href = '/dashboard';
      } else {
        const jsonResponse = await response.json();
        alert(jsonResponse.message);

        // Show the wait message
        submitMessage.innerText = 'Please wait 3 seconds before trying again.';
        submitMessage.style.display = 'block';

        setTimeout(() => {
          submitButton.disabled = false;
          submitMessage.innerText = '';
          submitMessage.style.display = 'none';
        }, 3000);
      }
    } catch (error) {
      console.error('Error during login:', error);
      alert('Error during login:', error);
      // Re-enable the submit button if there's an error
      submitButton.disabled = false;
    }
  });