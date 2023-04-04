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
      } 
      else if (response.status === 203) {
        alert('You need to modify your password');
        window.location.href = '/force-modify-password';
      }
      else {
        alert('Incorrect username or password');
        const jsonResponse = await response.json();
        console.log(jsonResponse);

        // Show the wait message
        submitMessage.innerText = 'Please wait ' + jsonResponse.lockoutTime + ' seconds before trying again.';
        submitMessage.style.display = 'block';

        setTimeout(() => {
          submitButton.disabled = false;
          submitMessage.innerText = '';
          submitMessage.style.display = 'none';
        }, 3000);
      }
    } catch (error) {
      console.error('Error during login:', error);
      alert('An error occurred during login');
      // Re-enable the submit button if there's an error
      submitButton.disabled = false;
    }
  });