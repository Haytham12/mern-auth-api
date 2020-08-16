const User = require("../models/user");
const jwt = require("jsonwebtoken");
const expressJwt = require("express-jwt");
const _ = require("lodash");
const { OAuth2Client } = require("google-auth-library");
const fetch = require("node-fetch");
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

exports.signup = (req, res) => {
  const { name, email, password } = req.body;
  User.findOne({ email }).exec((err, user) => {
    if (user) {
      return res.status(400).json({
        error: "Email is already exits",
      });
    }
    const token = jwt.sign(
      { name, email, password },
      process.env.JWT_ACCOUNT_ACTIVATION,
      { expiresIn: "10m" }
    );
    const emailData = {
      to: email,
      from: process.env.EMAIL_FROM,
      subject: "Account Activation",

      text: "and easy to do anywhere, even with Node.js",
      html: `
                <h1> Please click the following link to activate your account</h1>
                <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
                <hr />
                <p>This email may contain sensitive information</p>
                <p>${process.env.CLIENT_URL}</p>
            `,
    };
    sgMail
      .send(emailData)
      .then((sent) => {
        return res.json({
          message: `Email has been sent to: ${email}. Follow the instructions`,
        });
      })
      .catch((err) => {
        return res.json({
          message: err.message,
        });
      });
  });
};

exports.accountActivation = (req, res) => {
  const { token } = req.body;

  if (token) {
    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function (
      err,
      decoded
    ) {
      if (err) {
        console.log("JWT VERIFY ACTIVATION ERROR", err);
        return res.status(401).json({
          error: "Expired Link Signup again",
        });
      }
      const { name, email, password } = jwt.decode(token);
      const user = new User({ name, email, password });
      user.save((err, user) => {
        if (err) {
          console.log("SAVE USER IN ACCOUNT ACTIVATION ERROR: ", err);
          return res.status(401).json({
            error: "Error saving user in database, try signup again",
          });
        }
        return res.json({
          message: "Signup success. Please sign in",
        });
      });
    });
  } else {
    return res.json({
      message: "Some thing went wrong! Try again",
    });
  }
};

exports.signin = (req, res) => {
  const { email, password } = req.body;
  User.findOne({ email }).exec((err, user) => {
    if (err || !user) {
      res.status(400).json({
        error: "User with this email doesn not exists. Please signup",
      });
    }

    if (!user.authenticate(password)) {
      res.status(400).json({
        error: "Email and password do not match",
      });
    }

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    const { _id, name, email, role } = user;
    return res.json({
      token,
      user: { _id, name, email, role },
    });
  });
};

exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET, // req.user._id
});

exports.adminMiddleware = (req, res, next) => {
  User.findById({ _id: req.user._id }).exec((err, user) => {
    if (err || !user) {
      res.status(400).json({
        error: "User not found",
      });
    }
    if (user.role !== "admin") {
      res.status(400).json({
        error: "Admin resource Access denied",
        user,
      });
    }
    req.profile = user;
    next();
  });
};

exports.forgotPassword = (req, res) => {
  const { email } = req.body;
  User.findOne({ email }, (err, user) => {
    if (err || !user) {
      res.status(400).json({
        error: "This email does not exists",
      });
    }
    const token = jwt.sign(
      { _id: user._id, name: user.name },
      process.env.JWT_RESET_PASSWORD,
      {
        expiresIn: "10m",
      }
    );
    const emailData = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "Reset your Password link",
      html: `
        <h1>Please use the following link to reset your password</h1>
        <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
        <hr />
        <p>This email may contain sensitive information</p>
        <p>${process.env.CLIENT_URL}</p>
      `,
    };
    return user.updateOne({ resetPasswordLink: token }, (err, success) => {
      if (err) {
        console.log("RESET PASSWORD LINK ERROR", err);
        return res.status(400).json({
          error: "Database connection error on user password forgot request",
        });
      } else {
        sgMail
          .send(emailData)
          .then((sent) => {
            return res.json({
              message: `Email has been sent to ${email}, Please follow the instructions`,
            });
          })
          .catch((err) => {
            return res.json({
              message: err.message,
            });
          });
      }
    });
  });
};

exports.resetPassword = (req, res, next) => {
  const { resetPasswordLink, newPassword } = req.body;
  if (resetPasswordLink) {
    jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function (
      err,
      decoded
    ) {
      if (err) {
        return res.status(400).json({
          error: "Expired link, Please try again",
        });
      }
      User.findOne({ resetPasswordLink }, (err, user) => {
        if (err || !user) {
          return res.status(400).json({
            error: "Some thing went wrong",
          });
        }
        const updatedField = {
          password: newPassword,
          resetPasswordLink: "",
        };
        user = _.extend(user, updatedField);
        user.save((err, result) => {
          if (err) {
            return res.status(400).json({
              error: "Error resetting password",
            });
          }
          res.json({
            message: "Greate! Now you can log in with your new password",
          });
        });
      });
    });
  }
};

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
exports.googleLogin = (req, res) => {
  const { idToken } = req.body;
  client
    .verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID })
    .then((response) => {
      const { email_verified, name, email } = response.payload;
      if (email_verified) {
        User.findOne({ email }).exec((err, user) => {
          if (user) {
            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
              expiresIn: "7d",
            });
            const { _id, email, name, role } = user;
            return res.json({
              token,
              user: { _id, email, name, role },
            });
          } else {
            let password = email + process.env.JWT_SECRET;
            user = new User({ name, email, password });
            user.save((err, data) => {
              if (err) {
                console.log("ERROR GOOGLE LOGIN USER SAVE", err);
                return res.status(400).json({
                  error: "User signup failed with google",
                });
              }

              const token = jwt.sign(
                { _id: data._id },
                process.env.JWT_SECRET,
                { expiresIn: "7d" }
              );
              const { _id, email, name, role } = data;
              return res.json({
                token,
                user: { _id, email, name, role },
              });
            });
          }
        });
      } else {
        return res.status(400).json({
          error: "Google login failed, Try again",
        });
      }
    });
};

exports.facebookLogin = (req, res) => {
  console.log("FACEBOOK LOGIN REQ BODY", req.body);
  const { userID, accessToken } = req.body;
  const url = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`;
  return fetch(url, {
    method: "GET",
  })
    .then(response => response.json())
    .then(response => {
      const { email, name } = response;
      User.findOne({ email }).exec((err, user) => {
        if (user) {
          const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
          });
          const { _id, email, name, role } = user;
          return res.json({
            token,
            user: { _id, email, name, role },
          });
        } else {
          let password = email + process.env.JWT_SECRET;
          user = new User({ name, email, password });
          user.save((err, data) => {
            if (err) {
              console.log("ERROR FACEBOOK LOGIN USER SAVE", err);
              return res.status(400).json({
                error: "User signup failed with facebook",
              });
            }

            const token = jwt.sign({ _id: data._id }, process.env.JWT_SECRET, {
              expiresIn: "7d",
            });
            const { _id, email, name, role } = data;
            return res.json({
              token,
              user: { _id, email, name, role },
            });
          });
        }
      });
    })
    .catch(error => {
      res.json({
        error: 'Facebook login failed, Try later'
      })
    })
};
