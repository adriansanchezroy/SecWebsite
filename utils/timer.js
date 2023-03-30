const increaseTime = (loginAttempts,username) => {
  
    if(loginAttempts[username]){

        loginAttempts[username].count++;
        loginAttempts[username].lastTry = new Date();

    }else{

        loginAttempts[username] = { 

            count : 1,
            lastTry : new Date()

        }

    }
  
  };
  
  const resetTime = (loginAttempts,username) => {
  
    delete loginAttempts[username];
  
  
  };

  module.exports = increaseTime;
  module.exports = resetTime;