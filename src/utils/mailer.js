import nodemailer from "nodemailer";
import logger from "./logger.js";

// Function to replace placeholders in the template with actual values
function replacePlaceholders(template, values) {
  return template.replace(/{{(.*?)}}/g, (_, key) => values[key.trim()]);
}

// SMTP transporter configuration
const transporter = nodemailer.createTransport({
  service: process.env.SMTP_EMAIL_SERVICE,
  host: process.env.SMTP_EMAIL_HOST,
  port: process.env.SMTP_EMAIL_PORT,
  secure: true,
  auth: {
    user: process.env.SMTP_AUTH_EMAIL,
    pass: process.env.SMTP_AUTH_EMAIL_PASSWORD,
  },
});

const sendEmail = async (valueInput, recipientMails, template, subject) => {
  // Generate the final HTML content
  const htmlContent = replacePlaceholders(template, valueInput);

  // Email options
  const mailOptions = {
    from: `"Carderfly" <${process.env.SMTP_AUTH_EMAIL}>`,
    to: recipientMails,
    subject: subject,
    html: htmlContent,
  };

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      logger.error(`Error sending email: ${error}`);
      return;
    }
    logger.info(`Email sent: ${info.response}`);
  });
};

export { sendEmail };
