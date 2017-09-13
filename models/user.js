const mongoose = require('mongoose');
mongoose.Promise = global.Promise;
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Validate Function to check e-mail length
let emailLengthChecker = (email) => {
    // Check if e-mail exists
    if (!email) {
      return false; // Return error
    } else {
      // Check the length of e-mail string
      if (email.length < 5 || email.length > 30) {
        return false; // Return error if not within proper length
      } else {
        return true; // Return as valid e-mail
      }
    }
  };

  let validEmailChecker = (email) => {
    if (!email) {
        return false;
    } else {
        const regExp = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
        return regExp.test(email); // Return regular expression test results (true or false)    
    }
  };

  // Array of Email Validators
const emailValidators = [
    // First Email Validator
    {
      validator: emailLengthChecker,
      message: 'E-mail must be at least 5 characters but no more than 30'
    },
    {
        validator: validEmailChecker,
        message: 'Must be a valid e-mail'
    }
  ];

  let usernameLengthChecker = (username) => {
    if (!username) {
        return false; 
      } else {
        if (username.length < 3 || username.length > 15) {
          return false; 
        } else {
          return true; 
        }
      }
};

let validUsername = (username) => {
    if (!username) {
        return false;
    } else {
        const regExp = new RegExp(/^[a-zA-Z0-9]+$/);
        return regExp.test(username); // Return regular expression test result (true or false)
    }
  };

  const usernameValidators = [
    // First Email Validator
    {
      validator: usernameLengthChecker,
      message: 'Username must be 3 characters but no more than 15'
    },
    {
      validator: validUsername,
      message: 'Username must not have any special characters'
    }
  ];

  // Validate Function to check password length
let passwordLengthChecker = (password) => {
    // Check if password exists
    if (!password) {
      return false; // Return error
    } else {
      // Check password length
      if (password.length < 8 || password.length > 35) {
        return false; // Return error if passord length requirement is not met
      } else {
        return true; // Return password as valid
      }
    }
  };

    let validPassword = (password) => {
        if (!password) {
            return false;
        } else {
             // Regular Expression to test if password is valid format
            const regExp = new RegExp(/^(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[\d])(?=.*?[\W]).{8,35}$/);
            return regExp.test(password); // Return regular expression test result (true or false)
        }
      };

      // Array of Password validators
    const passwordValidators = [
        // First password validator
        {
        validator: passwordLengthChecker,
        message: 'Password must be at least 8 characters but no more than 35'
        },
        // Second password validator
        {
        validator: validPassword,
        message: 'Must have at least one uppercase, lowercase, special character, and number'
        }
    ];
  


const userSchema = new Schema({
    email: { type: String, required: true, unique: true, lowercase: true, validate: emailValidators },
    username: { type: String, required: true, unique: true, lowercase: true, validate: usernameValidators },
    password: { type: String, required: true, validate: passwordValidators } 
});



userSchema.pre('save', function(next) {
    if (!this.isModified('password'))
    return next();

    bcrypt.hash(this.password, null, null, (err, hash) => {
        if (err) return next(err);
        this.password = hash;
        next();
    });
});

// Methods to compare password to encrypted password upon login
userSchema.methods.comparePassword = function(password) {
  return bcrypt.compareSync(password, this.password); // Return comparison of login password to password in database (true or false)
};

module.exports = mongoose.model('User', userSchema);
