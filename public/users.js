// Get the modal, open modal button, and close button
const addUserModal = document.getElementById("addUserModal");
const openAddUserModalBtn = document.getElementById("openAddUserModal");
const closeAddUserModalBtn = document.querySelector(".close");

// Open the modal when the open modal button is clicked
openAddUserModalBtn.onclick = () => {
  addUserModal.style.display = "block";
};

// Close the modal when the close button is clicked
closeAddUserModalBtn.onclick = () => {
  addUserModal.style.display = "none";
};

// Close the modal when clicking outside of the modal content
window.onclick = (event) => {
  if (event.target === addUserModal) {
    addUserModal.style.display = "none";
  }
};

// Add user form submission
document.getElementById("addUserForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;
  const role = document.getElementById("role").value;

  if (password !== confirmPassword) {
    alert("Passwords do not match.");
    return;
  }
    // Perform the API request to create the user
    try {
        const response = await fetch("/addUser", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            password,
            role,
          }),
        });
    
        if (response.ok) {
          alert("User created successfully.");
          addUserModal.style.display = "none";
          // Refresh the users list
          window.location.reload();
        } else {
          const error = await response.json();
          alert(error.message);
        }
      } catch (error) {
        console.error("Error creating user:", error);
      }
    });
    