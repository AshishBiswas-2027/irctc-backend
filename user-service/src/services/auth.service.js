const { ConflictError, BadRequestError, ForbiddenError,UnauthorizedError } = require("../utils/error")
const {generateAndStoreOtp, verifyOtp} = require('../utils/otp');
const {sendOtpEmail, verifyOtpEmail} = require('../utils/email');
const {generateAccessToken, generateRefreshToken, verifyRefreshToken} = require('../utils/auth');
const bcrypt = require('bcrypt');
const prisma = require('../config/prisma');
const {redis} = require('../config/redis');
const { config } = require("../config");
const logger = require('../config/logger');
const jwt = require('jsonwebtoken');
const { generate } = require("otp-generator");
const {OAuth2Client} = require("google-auth-library");
const client = new OAuth2Client(config.GOOGLE_CLIENT_ID);

// gets data from auth controller 

//checks if user is already there 
// if there then error ; if not then hash password 
//store everything in meta variable 
//fir otp and otpsessionid generate karenge
//fir otp send karenge  
//otpsessionid auth.contoller ko wapas bhej denge 
const sendOTP = async(firstName, lastName, email, password) =>{
     const existingUser = await prisma.user.findUnique({
          where: {email}
     })

     if(existingUser){
          throw new ConflictError("user already exists");
     }
     const hashedPassword = await bcrypt.hash(password, 12);
     const meta = {firstName, lastName, email, hashedPassword};
     const {otp, otpSessionId} = await generateAndStoreOtp(meta);// in utils/otp.js
     await sendOtpEmail(email, otp);//in utils/email.js
     return {otpSessionId}
}


//verifyotp method is called fromm utils/otp.js
//if meta null then error 
//if meta not null then user create karna hai database me 
//fir verification mail bhjenge verifyOtpEmail se aur user ko return kar denge wapas auth.controller.js ko
const verifyOTP = async(otp, otpSessionId) =>{
     const meta = await verifyOtp(otp, otpSessionId);
     if(meta === null){
          throw new BadRequestError("Invalid or expired OTP", "OTP_INVALID");
     }
     const user = await prisma.user.create({
          data: {
               firstName: meta.firstName,
               lastName: meta.lastName,
               email: meta.email,
               password: meta.hashedPassword,
               emailVerified: true
          }
     })

     await verifyOtpEmail(meta);
     return user;

}

//validation-check if email exists or not and check password matches or not 
//access aaur refresh token ko generate karege
//password hata kar redis me store kar denge
//aur return kar denge controller me 
const login = async(email, password, deviceId) =>{
     const existingUser = await prisma.user.findUnique({
          where: {email}
     })
     if(!existingUser){
          throw new BadRequestError("Email not found")
     }
     const doesPasswordMatch = await bcrypt.compare(password, existingUser.password);
     if(!doesPasswordMatch){
          throw new BadRequestError("Incorrect Password");
     }
     const accessToken = generateAccessToken(existingUser.id);
     const refreshToken = generateRefreshToken(existingUser.id);
     const {jti} = jwt.decode(refreshToken);
     await redis.set(`refresh:${existingUser.id}:${deviceId}`, jti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
     const {password: _password, ...safeUser} = existingUser;
     await redis.set(`user:${existingUser.id}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);
     return {accessToken, refreshToken, loggedInUser: safeUser};
}

//paylod me se user id aur jti nikal lenge 
//stored jti redis se nikal lenge aur match kar lenge dono jti ko 
//if matches - then naya generate kar denge 
//if doesnt matches then error wapas login karna hai 
//sab naya generate kar k de denge 
const rotateRefreshToken = async(refreshToken, deviceId) =>{
     const payload = verifyRefreshToken(refreshToken);
     const {id: userId, jti} = payload;
     const storedJti = await redis.get(`refresh:${userId}:${deviceId}`);
     if(!storedJti){
          throw new ForbiddenError("Session Expired", "Login AGAIN")
     }
     if(storedJti !== jti){
          await redis.del(`refresh:${userId}:${deviceId}`);
          throw new ForbiddenError("Refresh token reused", "LOGIN AGAIN")
     }
     const newAccessToken = generateAccessToken(payload.id);
     const newRefreshToken = generateRefreshToken(payload.id);
     const {jti: newJti} = jwt.decode(newRefreshToken);
     await redis.set(`refresh:${payload.id}:${deviceId}`, newJti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
     return {newAccessToken, newRefreshToken};
}



//id token recieve karenge from controller 
//payload nikalenge aur check karenge sahi se mila hai k nahi 
//user create karenge aur refresh aur access token denge aur db me store karenge 
//1. pehle check karenge k authprovider table me exist karta hai k nahi agar karta hoga to tokens generate karege aur de denge toh simply user return kar denge 
//2. agar authprovider me nahi hai fir check karege k user table me hai k nahi agar nahi hai toh fir uska dono table me user aur auth provider me store kar denge because wo naya user hoga 
//3. par agar authprovider me nahi hai aur user me hai to fir auth provider me karenge kyu k wo pehhle kabhi normal otp se signup kar raha hoga aur wapas google se try kar raha hoga 

//access aur refresh token har caase me hi generate karenge 
const verifyGoogleIdToken = async(idToken, deviceId) =>{
     const ticket = await client.verifyIdToken({
          idToken,
          audience: config.GOOGLE_CLIENT_ID
     })
     const payload = ticket.getPayload();

     if(!payload.sub || !payload.email){
          throw new UnauthorizedError("Invalid Google Token Payload")
     }

     const googleUser = {
          provider: payload.iss,
          providerId: payload.sub,
          email: payload.email,
          firstName: payload.given_name,
          lastName: payload.family_name,
          emailVerified: payload.email_verified || false
     }

//transaction ka use karnge k ek id create karte time agar user dusre account se karna chahe toh na kar paaye 
     const user = await prisma.$transaction(async (tx) =>{
          let googleAuth = await tx.authProvider.findUnique({
               where: {
                    provider_providerId: {
                         provider: googleUser.provider,
                         providerId: googleUser.providerId
                    }
               },
               include: {user: true}
          })
//if present in authprovider simply return
          if(googleAuth){
               return googleAuth.user;
          }
//agar nahi hai toh check karenge k user table me hai k nahi 
          let existingUser = await tx.user.findUnique({
               where: {email: googleUser.email}
          })
// if user table me hai toh authprovider table me b user ka entry kar denge aur user return kar denge 
          if(existingUser){
               await tx.authProvider.create({
                    data: {
                         provider: googleUser.provider,
                         providerId: googleUser.providerId,
                         userId: existingUser.id
                    }
               })
               return existingUser;
          }
//agar user me b nahi hai aur authprovider me b nahi hai toh fir dono me entry karna hai aur return karna hai 
          return await tx.user.create({
               data: {
                    email: googleUser.email,
                    firstName: googleUser.firstName,
                    lastName: googleUser.lastName,
                    emailVerified: googleUser.emailVerified,
                    AuthProviders: {
                         create: {
                              provider: googleUser.provider,
                              providerId: googleUser.providerId
                         }
                    }
               }
          })
     })

     const accessToken = generateAccessToken(user.id);
     const refreshToken = generateRefreshToken(user.id);
     const {jti} = jwt.decode(refreshToken);
     await redis.set(`refresh:${user.id}:${deviceId}`, jti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
     const {password: _password, ...safeUser} = user;
     await redis.set(`user:${user.id}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);
     return {accessToken, refreshToken, loggedInUser: safeUser};
     
}


module.exports = {sendOTP, verifyOTP, login, rotateRefreshToken, verifyGoogleIdToken}
