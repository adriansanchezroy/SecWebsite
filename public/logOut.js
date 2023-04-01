const logoutButton = document.getElementById('logout');

logoutButton.addEventListener('click', async () => {
  try {
    const response = await fetch('/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (response.status === 200) {
      window.location.href = '/login';
    } else {
      alert('An error occurred while logging out');
    }
  } catch (error) {
    console.error('Error during logout:', error);
    alert('An error occurred during logout');
  }
});
