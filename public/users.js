const addUserModal = document.getElementById("addUserModal");
const openAddUserModalBtn = document.getElementById("addUserModal");
const closeAddUserModalBtn = document.querySelector(".close");

const addRoleButtons = document.querySelectorAll(".addRole");


openAddUserModalBtn.onclick = () => {
  addUserModal.style.display = "block";
};

closeAddUserModalBtn.onclick = () => {
  addUserModal.style.display = "none";
};

// Close the modal when clicking outside of the modal
window.onclick = (event) => {
  if (event.target === addUserModal) {
    addUserModal.style.display = "none";
  }
};

// Add user form submission
document.getElementById("addUserForm").addEventListener("submit", async (event) => {
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
