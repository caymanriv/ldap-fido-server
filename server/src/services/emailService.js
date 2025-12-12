import nodemailer from 'nodemailer';
import { isDebugEnabled, logger } from '../utils/logger.js';

class EmailService {
  constructor() {
    // Log SMTP configuration (without password)
    logger.debug('SMTP Configuration:', {
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
      user: process.env.SMTP_USER,
      from: process.env.SMTP_EMAIL_FROM_ADDRESS,
      tlsRejectUnauthorized: process.env.NODE_ENV !== 'production'
    });

    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      },
      tls: {
        // Do not fail on invalid certs in development
        rejectUnauthorized: process.env.NODE_ENV === 'production',
        // Support self-signed certificates
        ciphers: 'SSLv3'
      },
      // Extended timeout for container networking
      connectionTimeout: 30000, // 30 seconds
      greetingTimeout: 10000,   // 10 seconds
      socketTimeout: 60000,     // 60 seconds
      // Additional debug information
      debug: isDebugEnabled(),
      logger: isDebugEnabled()
    });
    
    // Verify connection on initialization
    this.verifyConnection().catch(error => {
      console.error('Initial SMTP connection verification failed:', error.message);
    });
  }

  /**
   * Verify SMTP connection
   * @returns {Promise<boolean>} - True if connection is successful
   */
  async verifyConnection() {
    try {
      await this.transporter.verify();
      console.log('SMTP server is ready to take our messages');
      return true;
    } catch (error) {
      console.error('SMTP connection error:', error);
      throw new Error(`SMTP connection failed: ${error.message}`);
    }
  }

  /**
   * Send a TOTP code to the user's email
   * @param {string} email - User's email address
   * @param {string} code - The TOTP code
   * @returns {Promise<boolean>} - True if email was sent successfully
   */
  async sendTotpEmail(email, code) {
    const mailOptions = {
      from: `"${process.env.SMTP_EMAIL_FROM_NAME}" <${process.env.SMTP_EMAIL_FROM_ADDRESS}>`,
      to: email,
      subject: 'Your Verification Code',
      text: `Your verification code is: ${code}\n\nThis code will expire in 10 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Verification Code</h2>
          <p>Your verification code is:</p>
          <div style="
            font-size: 24px; 
            font-weight: bold; 
            letter-spacing: 5px; 
            margin: 20px 0; 
            padding: 15px; 
            background-color: #f5f5f5; 
            display: inline-block; 
            border-radius: 4px;
            border: 1px solid #ddd;
          ">
            ${code}
          </div>
          <p>This code will expire in 10 minutes.</p>
          <p>If you didn't request this code, please ignore this email.</p>
        </div>
      `,
      // Add headers for better tracking
      headers: {
        'X-Laziness-level': '1000',
        'X-Auto-Response-Suppress': 'OOF, AutoReply',
        'Precedence': 'bulk'
      }
    };

    try {
      // Verify connection first
      await this.verifyConnection();
      
      // Send the email
      const info = await this.transporter.sendMail(mailOptions);
      
      console.log('Email sent:', {
        messageId: info.messageId,
        envelope: info.envelope,
        accepted: info.accepted,
        rejected: info.rejected,
        pending: info.pending,
        response: info.response
      });
      
      return true;
      
    } catch (error) {
      console.error('Failed to send email:', {
        error: error.message,
        code: error.code,
        command: error.command,
        response: error.response,
        responseCode: error.responseCode,
        responseMessage: error.responseMessage,
        stack: error.stack
      });
      
      throw new Error(`Failed to send verification email: ${error.message}`);
    }
  }
}

// Export a singleton instance
const emailService = new EmailService();
export default emailService;
