// authMiddleware.js
const jwt = require('jsonwebtoken');
const config = require('../config/config.js');
const fs = require('fs');
const path = require('path');
const useragent = require('useragent');

// Log file path
const logFilePath = path.join(__dirname, 'request_logs.txt');

// Function to log messages
const logRequest = (message) => {
  const logEntry = `${new Date().toISOString()} - ${message}\n`;
  fs.appendFile(logFilePath, logEntry, (err) => {
    if (err) console.error('Error writing to log file:', err);
  });
};


const authenticationMiddleware = (req, res, next) => {
 // Get token from header
 let token;
  
 // Step 3: Parse the 'Cookie' header to extract the 'token'
 const cookies = req.headers.cookie.split('; ');

 cookies.forEach(cookie => {
    if(cookie.startsWith('token=')) {
      token = cookie.split('=')[1];
    }
 });

  // Check if token doesn't exist
  if (!token) {
    return res.status(401).json({ msg: 'Authorization denied' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, config.jwtSecret);
    // Add user from token payload
    req.user = decoded.user;
    next();
  } catch (err) {
    // Clear cookie
    res.cookie('token', '', { expires: new Date(0), httpOnly: true, secure: false, sameSite: 'Lax' });
    res.status(401).json({ msg: 'Token is not valid' });
  }
};


const superAdminMiddleware = (req, res, next) => {
  // Get token from header
  let token;
  
      // Step 3: Parse the 'Cookie' header to extract the 'token'
  const cookies = req.headers.cookie.split('; ');
  
  cookies.forEach(cookie => {
    if (cookie.startsWith('token=')) {
      token = cookie.split('=')[1];
    }
  });


  // Check if token doesn't exist
  if (!token) {
    return res.status(401).json({ msg: 'Authorization denied' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, config.jwtSecret);
    // Check if the user is a superadmin
    if (decoded.user.role !== 'superadmin') {
      return res.status(403).json({ msg: 'Not authorized' });
    }
    // Add user from token payload
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

const adminMiddleware = (req, res, next) => {
 // Get token from header
 let token;
  
 // Step 3: Parse the 'Cookie' header to extract the 'token'
 const cookies = req.headers.cookie.split('; ');

 cookies.forEach(cookie => {
  if (cookie.startsWith('token=')) {
    token = cookie.split('=')[1];
  }
 });

  // Check if token doesn't exist
  if (!token) {
    return res.status(401).json({ msg: 'Authorization denied' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, config.jwtSecret);
    // Check if the user is an admin
    if (decoded.user.role !== 'admin') {
      return res.status(403).json({ msg: 'Not authorized' });
    }
    // Add user from token payload
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// const verifyToken = (req, res, next) => {

//   // Get token from header
//   let token;
//   console.log("auth ", req.headers.authorization)
//   console.log("cookie ",req.headers.cookie)

//   if(req.headers.authorization && req.headers.authorization !== ''){
//     token = req.headers.authorization
//     console.log("if")
//   }else{
//     console.log("else")
//     const cookies = req.headers.cookie?.split('; ');
  
//     cookies.forEach(cookie => {
//       if (cookie.startsWith('token=')) {
//         token = cookie?.split('=')[1];
//       }
//     });
//   }
//   // Step 3: Parse the 'Cookie' header to extract the 'token'

//   console.log("token ",token)
//   // Check if token doesn't exist
//   if (!token) {
//     return res.status(200).json({ success:false,msg: 'Authorization denied' });
//   }

//   try {
//     // Verify token
//     const decoded = jwt.verify(token, config.jwtSecret);
//     res.status(200).json({ success:true,msg: 'User is authorized' });
//   } catch (err) {
//     console.log("error",err)
//     res.status(200).json({ success:false,msg: 'Token is not valid' });
//   }
// };
const verifyToken = (req, res, next) => {
  // Get IP address
  const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  // Get user-agent details (browser, device, etc.)
  const agent = useragent.parse(req.headers['user-agent']);
  const browser = agent.toAgent(); // Example: "Chrome 89.0.4389"
  const os = agent.os.toString();  // Example: "Windows 10"
  const device = agent.device.toString(); // Example: "Desktop"

  // Log user info
  logRequest(`Request from IP: ${ipAddress}, Browser: ${browser}, OS: ${os}, Device: ${device}`);

  // Get token from header or cookies
  let token;

  if (req.headers.authorization && req.headers.authorization !== '') {
    token = req.headers.authorization;

    // Log the token
    logRequest(`Token From Auth: ${token ? token + config.jwtSecret : 'No token provided'}`);
  } else {
    console.log("Checking cookies for token.");
    const cookies = req.headers.cookie?.split('; ');

    cookies?.forEach(cookie => {
      if (cookie.startsWith('token=')) {
        token = cookie?.split('=')[1];
      }
    });
    // Log the token
    logRequest(`Token From Cookie: ${token ? token + config.jwtSecret : 'No token provided'}`);

  }

  

  // Check if token doesn't exist
  if (!token) {
    logRequest('Authorization denied - No token.');
    return res.status(200).json({ success: false, msg: 'Authorization denied' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, config.jwtSecret);
    logRequest('Token is valid, user authorized.');
    res.status(200).json({ success: true, msg: 'User is authorized' });
  } catch (err) {
    logRequest(`Invalid token - Error: ${err.message}`);
    res.status(200).json({ success: false, msg: 'Token is not valid' });
  }
};
module.exports = {
  authenticationMiddleware,
  superAdminMiddleware,
  adminMiddleware,
  verifyToken
}

