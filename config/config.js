// config.js

module.exports = {
  database: {
    user: process.env.user,
    host: process.env.host,
    database: process.env.database,
    password: process.env.password,
    // user: 'root',
    // host: 'localhost',
    // database: 'thepankh',
    // password: 'SrjaSky@@9643@@thepankh@@artithapa',
  },
  jwtSecret: process.env.jwtSecret,
  PORT: process.env.PORT || 3001,
  NODE_ENV: process.env.NODE_ENV,
  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_PORT: process.env.SMTP_PORT,
  SMTP_PASSWORD: process.env.SMTP_PASSWORD,
  SMTP_MAIL: process.env.SMTP_MAIL,
  JWT_EXPIRES_TIME: process.env.JWT_EXPIRES_TIME,
  COOKIE_EXPIRE: process.env.COOKIE_EXPIRE,
  JWT_SECRET: process.env.JWT_SECRET,
  CLOUDINARY_NAME: process.env.CLOUDINARY_NAME,
  CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET: process.env.CLOUDINARY_API_SECRET,
};
