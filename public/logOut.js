const logoutButton = document.getElementById('logout-form');

logoutButton.addEventListener('click', async () => {
  try {
    const response = await fetch('/logout', {
      method: 'POST'
    });

    if (response.status === 200) {
      document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      window.location.href = '/login';
    } else {
      alert('Logout failed');
    }
  } catch (error) {
    console.error('Error during logout:', error);
    alert('An error occurred during logout');
  }
});
