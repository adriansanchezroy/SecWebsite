// Get the modal, open modal button, and close button
const addUserModal = document.getElementById("addUserModal");
const openAddUserModalBtn = document.getElementById("openAddUserModal");
const closeAddUserModalBtn = document.querySelector(".close");
const addUserForm = document.getElementById("addUserForm");

const addRoleButtons = document.querySelectorAll(".dropdown-item");

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
addUserForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const firstName = document.getElementById("firstName").value;
  const lastName = document.getElementById("lastName").value;
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
            firstName,
            lastName,
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

addRoleButtons.forEach((button) => {
  button.addEventListener("click", async (event) => {
    event.preventDefault();
    const userId = event.target.dataset.userid;
    const role = event.target.dataset.role;
    try {
      const response = await fetch(`/addRole/${userId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role }),
      });
      if (response.ok) {
        alert(`Role ${role} added successfully.`);
        window.location.reload();
      } else {
        const error = await response.json();
        alert(error.message);
      }
    } catch (error) {
      console.error("Error adding role:", error);
    }
  });
});    