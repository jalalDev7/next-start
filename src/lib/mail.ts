import nodemailer from "nodemailer";

// email infos
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAILING_EMAIL,
    pass: process.env.MAILING_PASSWORD,
  },
});

export const sendVerificationEmail = async (email: string, token: string) => {
  const confirmLink = `http://localhost:3000/auth/new-verification?token=${token}`;

  const mailOptions = {
    from: "technochtak3@gmail.com",
    to: email,
    subject: "Email verification",
    text: `Click to confirm email : ${confirmLink}`,
  };

  transporter.sendMail(mailOptions, function (error) {
    if (error) {
      console.log(error);
    }
  });
};

export const sendResetPasswordEmail = async (email: string, token: string) => {
  const confirmLink = `http://localhost:3000/auth/new-password?token=${token}`;

  const mailOptions = {
    from: "technochtak3@gmail.com",
    to: email,
    subject: "Reset Password",
    text: `Click to reset password : ${confirmLink}`,
  };

  transporter.sendMail(mailOptions, function (error) {
    if (error) {
      console.log(error);
    }
  });
};
